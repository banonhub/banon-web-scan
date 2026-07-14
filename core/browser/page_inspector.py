from __future__ import annotations

from selenium.webdriver.common.by import By

from core.config.settings import ScannerSettings
from core.runtime.entities import (
    Barrier,
    ControlTarget,
    FormTarget,
    PageInventory,
)
from core.browser.browsing_context import BrowsingContext
from core.browser.wait_strategy import WaitStrategy


class PageInspector:
    """Inventory documents, nested frames, and open Shadow DOM at runtime."""

    def __init__(self, driver, settings: ScannerSettings):
        self.driver = driver
        self.settings = settings
        self.contexts = BrowsingContext(driver, settings)
        self.wait = WaitStrategy(driver, settings)
        self.barriers: list[Barrier] = []

    def inspect_url(self, url: str) -> PageInventory:
        self.driver.get(url)
        self.wait.page_ready()
        return self.inspect_current()

    def inspect_current(self) -> PageInventory:
        self.barriers = []
        aggregate = PageInventory(
            url=self.driver.current_url,
            title=self.driver.title,
            body_text="",
        )
        max_depth = int(self.settings.get("inspection", "maximum_frame_depth"))
        self._inspect_context((), aggregate, max_depth)
        self.contexts.reset()
        aggregate.links = list(dict.fromkeys(aggregate.links))
        aggregate.messages = list(dict.fromkeys(aggregate.messages))
        return aggregate

    def _inspect_context(
        self,
        frame_path: tuple[int, ...],
        aggregate: PageInventory,
        remaining_depth: int,
    ) -> None:
        try:
            self.contexts.activate(frame_path)
            raw = self.driver.execute_script(
                self._inventory_script(),
                self._effective_inspection(),
                "-".join(str(index) for index in frame_path) or "root",
            )
        except Exception as exc:
            self.barriers.append(
                Barrier(
                    kind="inaccessible_frame",
                    url=self.driver.current_url,
                    detail=f"{frame_path}: {exc}",
                )
            )
            return

        if not frame_path:
            aggregate.url = raw.get("url") or aggregate.url
            aggregate.title = raw.get("title") or aggregate.title
            aggregate.body_text = raw.get("body_text") or ""
        aggregate.links.extend(raw.get("links", []))
        aggregate.messages.extend(raw.get("messages", []))
        aggregate.captcha_detected = (
            aggregate.captcha_detected or bool(raw.get("captcha_detected"))
        )
        aggregate.shadow_root_count += int(raw.get("shadow_root_count", 0))

        for control in raw.get("controls", []):
            aggregate.controls.append(
                ControlTarget(
                    element_id=control["element_id"],
                    frame_path=frame_path,
                    tag=control["tag"],
                    control_type=control["control_type"],
                    name=control["name"],
                    html_id=control["html_id"],
                    role=control["role"],
                    label=control["label"],
                    placeholder=control["placeholder"],
                    autocomplete=control["autocomplete"],
                    text=control["text"],
                    required=bool(control["required"]),
                    visible=bool(control["visible"]),
                    enabled=bool(control["enabled"]),
                    form_id=control.get("form_id"),
                    shadow_depth=int(control.get("shadow_depth", 0)),
                    attributes=control.get("attributes", {}),
                )
            )

        for form in raw.get("forms", []):
            aggregate.forms.append(
                FormTarget(
                    element_id=form["element_id"],
                    frame_path=frame_path,
                    action=form["action"],
                    method=form["method"],
                    text=form["text"],
                    control_ids=tuple(form["control_ids"]),
                    has_password=bool(form["has_password"]),
                    shadow_depth=int(form.get("shadow_depth", 0)),
                    attributes=form.get("attributes", {}),
                )
            )

        if remaining_depth <= 0:
            return

        selector = self.settings.get("inspection", "frame_selector")
        try:
            self.contexts.activate(frame_path)
            frame_count = len(
                self.driver.find_elements(By.CSS_SELECTOR, selector)
            )
        except Exception:
            frame_count = 0
        aggregate.frame_count += frame_count
        for index in range(frame_count):
            self._inspect_context(
                (*frame_path, index),
                aggregate,
                remaining_depth - 1,
            )

    def _effective_inspection(self) -> dict:
        """Inspection config with any user ``--extra-selectors`` appended.

        The extra selectors are merged into ``control_selector`` so custom web
        components are inventoried alongside the built-in controls, without
        mutating the shared defaults document.
        """
        inspection = self.settings.get("inspection")
        extra = getattr(self.settings, "extra_selectors", None)
        if not extra:
            return inspection
        merged = dict(inspection)
        merged["control_selector"] = ", ".join(
            [inspection["control_selector"], *extra]
        )
        return merged

    @staticmethod
    def _inventory_script() -> str:
        return """
        const config = arguments[0];
        const contextToken = arguments[1];
        const marker = config.marker_attribute;
        let sequence = 0;
        let shadowCount = 0;
        let captchaDetected = false;
        const controls = [];
        const forms = [];
        const links = [];
        const messages = [];
        const seenControls = new Set();
        const seenForms = new Set();

        const clean = value => String(value || "").trim();
        const mark = element => {
          let value = element.getAttribute(marker);
          if (!value) {
            value = `banon-${contextToken}-${++sequence}`;
            element.setAttribute(marker, value);
          }
          return value;
        };
        const visible = element => {
          const style = getComputedStyle(element);
          const box = element.getBoundingClientRect();
          return style.display !== "none" && style.visibility !== "hidden" &&
            box.width > 0 && box.height > 0;
        };
        const labelFor = element => {
          if (element.labels && element.labels.length) {
            return Array.from(element.labels).map(label => clean(label.innerText))
              .filter(Boolean).join(" ");
          }
          const aria = clean(element.getAttribute("aria-label"));
          if (aria) return aria;
          const labelled = clean(element.getAttribute("aria-labelledby"));
          if (labelled) {
            const ownerRoot = element.getRootNode();
            return labelled.split(/\\s+/).map(id => {
              const node = ownerRoot.getElementById
                ? ownerRoot.getElementById(id)
                : document.getElementById(id);
              return node ? clean(node.innerText || node.textContent) : "";
            }).filter(Boolean).join(" ");
          }
          const wrapping = element.closest("label");
          return wrapping ? clean(wrapping.innerText || wrapping.textContent) : "";
        };
        const inspectRoot = (root, shadowDepth) => {
          captchaDetected = captchaDetected ||
            config.captcha_selectors.some(selector => {
              try { return Boolean(root.querySelector(selector)); }
              catch (_) { return false; }
            });
          for (const form of root.querySelectorAll("form")) {
            const formId = mark(form);
            if (!seenForms.has(formId)) {
              seenForms.add(formId);
              const members = Array.from(
                form.querySelectorAll(config.control_selector)
              );
              forms.push({
                element_id: formId,
                action: clean(form.action || location.href),
                method: clean(form.method || "get").toLowerCase(),
                text: clean(form.innerText || form.textContent),
                control_ids: members.map(mark),
                has_password: members.some(item =>
                  config.secret_control_types.includes(
                    clean(item.type).toLowerCase()
                  )
                ),
                shadow_depth: shadowDepth,
                attributes: {
                  enctype: clean(form.enctype),
                  novalidate: Boolean(form.noValidate)
                }
              });
            }
          }
          for (const element of root.querySelectorAll(config.control_selector)) {
            const elementId = mark(element);
            if (seenControls.has(elementId)) continue;
            seenControls.add(elementId);
            const owner = element.closest("form");
            controls.push({
              element_id: elementId,
              tag: clean(element.tagName).toLowerCase(),
              control_type: clean(
                element.type || element.getAttribute("role") || element.tagName
              ).toLowerCase(),
              name: clean(element.name),
              html_id: clean(element.id),
              role: clean(element.getAttribute("role")).toLowerCase(),
              label: labelFor(element),
              placeholder: clean(element.getAttribute("placeholder")),
              autocomplete: clean(element.getAttribute("autocomplete")),
              text: clean(element.innerText || element.value),
              required: Boolean(element.required ||
                element.getAttribute("aria-required") === "true"),
              visible: visible(element),
              enabled: !element.disabled &&
                element.getAttribute("aria-disabled") !== "true",
              form_id: owner ? mark(owner) : null,
              shadow_depth: shadowDepth,
              attributes: {
                accept: clean(element.getAttribute("accept")),
                href: clean(element.href || element.getAttribute("href")),
                target: clean(element.getAttribute("target")),
                download: clean(element.getAttribute("download")),
                multiple: Boolean(element.multiple),
                pattern: clean(element.getAttribute("pattern")),
                contenteditable: element.isContentEditable,
                minlength: Number(element.minLength || 0),
                maxlength: Number(element.maxLength || 0),
                readonly: Boolean(element.readOnly),
                inputmode: clean(element.getAttribute("inputmode"))
              }
            });
          }
          for (const link of root.querySelectorAll(config.link_selector)) {
            if (link.href) links.push(link.href);
          }
          for (const selector of config.message_selectors) {
            for (const node of root.querySelectorAll(selector)) {
              const text = clean(node.innerText || node.textContent);
              if (text && visible(node)) messages.push(text);
            }
          }
          for (const element of root.querySelectorAll("*")) {
            if (element.shadowRoot) {
              shadowCount += 1;
              inspectRoot(element.shadowRoot, shadowDepth + 1);
            }
          }
        };
        inspectRoot(document, 0);
        captchaDetected = captchaDetected ||
          config.captcha_text_markers.some(marker =>
          clean(document.body && document.body.innerText)
            .toLowerCase().includes(marker.toLowerCase())
        );
        return {
          url: location.href,
          title: document.title,
          body_text: clean(document.body && document.body.innerText),
          controls,
          forms,
          links,
          messages,
          captcha_detected: captchaDetected,
          shadow_root_count: shadowCount
        };
        """
