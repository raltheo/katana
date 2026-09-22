// This file contains utility JS functions that are utilised by
// the main crawling JS code to perform actions.
(function initUtilityFunctions() {
    // getElementAttributes returns the attributes of an element
    window.getElementAttributes = function (element) {
      const attrs = {};
      for (let attr of element.attributes) {
        attrs[attr.name] = attr.value;
      }
      return attrs;
    };
  
    // _elementDataFromElement returns the data for an element
    window._elementDataFromElement = function (el) {
      let visible = false;
      let pointerEventsNone = false;
      let cursor = '';
      try {
        const style = el.ownerDocument.defaultView.getComputedStyle(el);
        pointerEventsNone = style.pointerEvents === 'none';
        cursor = String(style.cursor || '');
        const rects = el.getClientRects();
        visible = !el.hidden &&
          style.display !== 'none' &&
          style.visibility !== 'hidden' &&
          style.visibility !== 'collapse' &&
          Number(style.opacity || 1) > 0 &&
          rects.length > 0 &&
          Array.from(rects).some((rect) => rect.width > 0 && rect.height > 0);
        if (visible && typeof el.checkVisibility === 'function') {
          visible = el.checkVisibility({
            checkOpacity: true,
            checkVisibilityCSS: true,
          });
        }
      } catch (_) {}
      const disabled = Boolean(
        el.disabled ||
        el.hasAttribute('disabled') ||
        ['true', '1'].includes(String(el.getAttribute('aria-disabled') || '').toLowerCase()) ||
        el.classList.contains('cursor-not-allowed')
      );
      return {
        tagName: el.tagName,
        id: el.id,
        classes: typeof el.className === 'string' ? el.className : Array.from(el.classList).join(' '),
        attributes: window.getElementAttributes(el),
        hidden: el.hidden,
        visible: visible,
        cursor: cursor,
        pointerEventsNone: pointerEventsNone || el.classList.contains('pointer-events-none'),
        disabled: disabled,
        outerHTML: el.outerHTML,
        name: el.name,
        type: el.type,
        value: el.value != null ? String(el.value) : '',
        textContent: el.textContent.trim(),
        xpath: window.getXPath(el),
        cssSelector: window.getCssPath(el),
        deepLocator: window.getDeepLocator(el),
        documentURL: String(el.ownerDocument?.location?.href || ''),
      };
    };

    // getDeepLocator builds a selector path that can cross open shadow roots
    // and same-origin iframe documents. Each selector is relative to the root
    // selected by the preceding step.
    window.getDeepLocator = function (el) {
      if (!el || el.nodeType !== Node.ELEMENT_NODE) return [];
      const locator = [{ type: 'element', selector: window.getCssPath(el) }];
      let root = el.getRootNode();
      const seen = new Set();
      while (root && root !== document && !seen.has(root)) {
        seen.add(root);
        if (root.nodeType === Node.DOCUMENT_FRAGMENT_NODE && root.host) {
          locator.unshift({ type: 'shadow', selector: window.getCssPath(root.host) });
          root = root.host.getRootNode();
          continue;
        }
        if (root.nodeType === Node.DOCUMENT_NODE) {
          let frame = null;
          try { frame = root.defaultView?.frameElement || null; } catch (_) {}
          if (!frame) break;
          locator.unshift({ type: 'iframe', selector: window.getCssPath(frame) });
          root = frame.getRootNode();
          continue;
        }
        break;
      }
      return locator;
    };

    window.getElementFromDeepLocator = function (locator) {
      try {
        if (!Array.isArray(locator) || locator.length === 0) return null;
        let root = document;
        for (const step of locator) {
          if (!step || !step.selector || !root?.querySelector) return null;
          const element = root.querySelector(step.selector);
          if (!element) return null;
          if (step.type === 'shadow') {
            root = element.shadowRoot;
          } else if (step.type === 'iframe') {
            root = element.contentDocument;
          } else if (step.type === 'element') {
            return element;
          } else {
            return null;
          }
          if (!root) return null;
        }
      } catch (_) {}
      return null;
    };

    window.getElementDataFromDeepLocator = function (locator) {
      const element = window.getElementFromDeepLocator(locator);
      return element ? window._elementDataFromElement(element) : null;
    };

    // Visit the top document, every open shadow root and every accessible
    // same-origin iframe. Cross-origin frames remain observable through CDP
    // network capture but cannot safely expose their DOM to page JavaScript.
    window.forEachDeepRoot = function (callback) {
      const seen = new Set();
      const visit = (root) => {
        if (!root || seen.has(root) || !root.querySelectorAll) return;
        seen.add(root);
        callback(root);
        let elements = [];
        try { elements = Array.from(root.querySelectorAll('*')); } catch (_) {}
        for (const element of elements) {
          if (element.shadowRoot) visit(element.shadowRoot);
          if (element.tagName === 'IFRAME') {
            try { if (element.contentDocument) visit(element.contentDocument); } catch (_) {}
          }
        }
      };
      visit(document);
    };
  
    // getAllElements returns all the elements for a query
    // selector on the page
    window.getAllElements = function (selector) {
      const results = [];
      const seen = new Set();
      window.forEachDeepRoot((root) => {
        try {
          for (const el of root.querySelectorAll(selector)) {
            if (seen.has(el)) continue;
            seen.add(el);
            results.push(window._elementDataFromElement(el));
          }
        } catch (_) {}
      });
      return results;
    };

    window.getElementFromXPath = function (xpath) {
      try {
        const element = document
          .evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null)
          .singleNodeValue;
        return element ? _elementDataFromElement(element) : null;
      } catch (_) {
        return null;
      }
    }
  
    // getAllElementsWithEventListeners returns all the elements
    // on the page along with their event listeners
    // TODO: Is it optimized? or do we need to do something else?
    window.getAllElementsWithEventListeners = function () {
      const elementsWithListeners = [];
      window.forEachDeepRoot((root) => {
        for (const el of root.querySelectorAll('*')) {
          const listeners = getEventListeners(el);
          if (listeners && listeners.length) {
            elementsWithListeners.push({
              element: window._elementDataFromElement(el),
              listeners: listeners,
            });
          }
        }
      });
      return elementsWithListeners;
    };

    window.getAllRegisteredEventListeners = function () {
      const results = [];
      const seenWindows = new Set();
      window.forEachDeepRoot((root) => {
        const frameWindow = root.nodeType === Node.DOCUMENT_NODE
          ? root.defaultView
          : root.ownerDocument?.defaultView;
        if (!frameWindow || seenWindows.has(frameWindow)) return;
        seenWindows.add(frameWindow);
        let registered = [];
        try { registered = frameWindow.__eventListeners || []; } catch (_) {}
        for (const item of registered) {
          const target = item.targetElement;
          const element = target?.isConnected
            ? window._elementDataFromElement(target)
            : item.element;
          if (!element) continue;
          results.push({
            element,
            type: item.type,
            listener: item.listener,
            options: item.options || {},
          });
        }
      });
      return results;
    };
  
    // getEventListeners returns all the event listeners
    // attached to an element
    function getEventListeners(element) {
      const listeners = [];
      for (let event in element) {
        if (event.startsWith("on")) {
          const listener = element[event];
          if (typeof listener === "function") {
            listeners.push({
              type: event,
              listener: listener.toString(),
            });
          }
        }
      }
      return listeners;
    }
  
    // getAllForms returns all the forms on the page
    // along with their elements
    window.getAllForms = function () {
      const allForms = [];
      window.forEachDeepRoot((root) => {
        try { allForms.push(...root.querySelectorAll('form, div.form')); } catch (_) {}
      });
      return allForms.map((form) => ({
        tagName: form.tagName,
        id: form.id,
        classes: typeof form.className === 'string' ? form.className : Array.from(form.classList).join(' '),
        attributes: window.getElementAttributes(form),
        outerHTML: form.outerHTML,
        action: form.action ? String(form.action) : '',
        method: form.method,
        xpath: window.getXPath(form),
        cssSelector: window.getCssPath(form),
        deepLocator: window.getDeepLocator(form),
        elements: form.elements ? 
          Array.from(form.elements).map((el) => _elementDataFromElement(el)) :
          Array.from(form.querySelectorAll('input, select, textarea, button')).map((el) => _elementDataFromElement(el))
      }));
    };
  
    // Copyright (C) Chrome Authors
    // The below code is part of the Chrome DevTools project
    // and is adapted from there.
  
    // Utility to get the CSS selector path for an element.
    window.getCssPath = function (node, optimized = false) {
      if (node.nodeType !== Node.ELEMENT_NODE) return "";
  
      const steps = [];
      let contextNode = node;
      while (contextNode) {
        const step = window._cssPathStep(
          contextNode,
          optimized,
          contextNode === node
        );
        if (!step) break; // Error - bail out early.
        steps.push(step.value);
        if (step.optimized) break;
        contextNode = contextNode.parentNode;
      }
  
      steps.reverse();
      return steps.join(" > ");
    };
  
    // Utility to get the XPath for an element.
    window.getXPath = function (node, optimized = false) {
      if (node.nodeType === Node.DOCUMENT_NODE) return "/";
  
      const steps = [];
      let contextNode = node;
      while (contextNode) {
        const step = window._xPathValue(contextNode, optimized);
        if (!step) break; // Error - bail out early.
        steps.push(step.value);
        if (step.optimized) break;
        contextNode = contextNode.parentNode;
      }
  
      steps.reverse();
      return (steps.length && steps[0].optimized ? "" : "/") + steps.join("/");
    };
  
    // Helper to create a step in the CSS path.
    window._cssPathStep = function (node, optimized, isTargetNode) {
      if (node.nodeType !== Node.ELEMENT_NODE) return null;
  
      const id = node.getAttribute("id");
      if (optimized) {
        if (id) return {
          value: `#${window.escapeIdentifierIfNeeded(id)}`,
          optimized: true,
        };
        const nodeNameLower = node.nodeName.toLowerCase();
        if (
          nodeNameLower === "body" ||
          nodeNameLower === "head" ||
          nodeNameLower === "html"
        )
          return { value: node.nodeName, optimized: true };
      }
      const nodeName = node.nodeName;
  
      if (id) return {
        value: `${nodeName}#${window.escapeIdentifierIfNeeded(id)}`,
        optimized: true,
      };
      const parent = node.parentNode;
      if (!parent || parent.nodeType === Node.DOCUMENT_NODE)
        return { value: nodeName, optimized: true };
  
      const prefixedOwnClassNamesArray = window.prefixedElementClassNames(node);
      let needsClassNames = false;
      let needsNthChild = false;
      let ownIndex = -1;
      let elementIndex = -1;
      const siblings = parent.children;
      for (
        let i = 0;
        (ownIndex === -1 || !needsNthChild) && i < siblings.length;
        ++i
      ) {
        const sibling = siblings[i];
        if (sibling.nodeType !== Node.ELEMENT_NODE) continue;
        elementIndex += 1;
        if (sibling === node) {
          ownIndex = elementIndex;
          continue;
        }
        if (needsNthChild) continue;
        if (sibling.nodeName.toLowerCase() !== nodeName.toLowerCase()) continue;
  
        needsClassNames = true;
        const ownClassNames = new Set(prefixedOwnClassNamesArray);
        if (!ownClassNames.size) {
          needsNthChild = true;
          continue;
        }
        const siblingClassNamesArray = window.prefixedElementClassNames(sibling);
        for (let j = 0; j < siblingClassNamesArray.length; ++j) {
          const siblingClass = siblingClassNamesArray[j];
          if (!ownClassNames.has(siblingClass)) continue;
          ownClassNames.delete(siblingClass);
          if (!ownClassNames.size) {
            needsNthChild = true;
            break;
          }
        }
      }
  
      let result = nodeName;
      if (
        isTargetNode &&
        nodeName.toLowerCase() === "input" &&
        node.getAttribute("type") &&
        !node.getAttribute("id") &&
        !node.getAttribute("class")
      )
        result += '[type="' + node.getAttribute("type") + '"]';
      if (needsNthChild) {
        result += `:nth-child(${ownIndex + 1})`;
      } else if (needsClassNames) {
        for (const prefixedName of prefixedOwnClassNamesArray)
          result += "." + window.escapeIdentifierIfNeeded(prefixedName.substr(1));
      }
  
      return { value: result, optimized: false };
    };
  
    // Helper to get class names prefixed with '$' for mapping purposes.
    window.prefixedElementClassNames = function (node) {
      const classAttribute = node.getAttribute("class");
      if (!classAttribute) return [];
  
      return classAttribute
        .split(/\s+/g)
        .filter(Boolean)
        .map(function (name) {
          return "$" + name;
        });
    };
  
    // Helper to escape identifiers for use in CSS selectors.
    window.escapeIdentifierIfNeeded = function (ident) {
      if (window.isCSSIdentifier(ident)) return ident;
      const shouldEscapeFirst = /^(?:[0-9]|-[0-9-]?)/.test(ident);
      const lastIndex = ident.length - 1;
      return ident.replace(/./g, function (c, i) {
        return (shouldEscapeFirst && i === 0) || !window.isCSSIdentChar(c)
          ? window.escapeAsciiChar(c, i === lastIndex)
          : c;
      });
    };
  
    // Helper to determine if a character is valid in a CSS identifier.
    window.isCSSIdentChar = function (c) {
      if (/[a-zA-Z0-9_-]/.test(c)) return true;
      return c.charCodeAt(0) >= 0xa0;
    };
  
    // Helper to determine if a string is a valid CSS identifier.
    window.isCSSIdentifier = function (value) {
      return /^-{0,2}[a-zA-Z_][a-zA-Z0-9_-]*$/.test(value);
    };
  
    // Helper to escape ASCII characters for use in CSS selectors.
    window.escapeAsciiChar = function (c, isLast) {
      return (
        "\\" + c.charCodeAt(0).toString(16).padStart(2, "0") + (isLast ? "" : " ")
      );
    };
  
    // Helper to get the XPath step for a node.
    window._xPathValue = function (node, optimized) {
      let ownValue;
      const ownIndex = window._xPathIndex(node);
      if (ownIndex === -1) return null;
  
      switch (node.nodeType) {
        case Node.ELEMENT_NODE:
          if (optimized && node.getAttribute("id"))
            return {
              value: `//*[@id="${node.getAttribute("id")}"]`,
              optimized: true,
            };
          ownValue = node.localName;
          break;
        case Node.ATTRIBUTE_NODE:
          ownValue = "@" + node.nodeName;
          break;
        case Node.TEXT_NODE:
        case Node.CDATA_SECTION_NODE:
          ownValue = "text()";
          break;
        case Node.PROCESSING_INSTRUCTION_NODE:
          ownValue = "processing-instruction()";
          break;
        case Node.COMMENT_NODE:
          ownValue = "comment()";
          break;
        case Node.DOCUMENT_NODE:
          ownValue = "";
          break;
        default:
          ownValue = "";
          break;
      }
  
      if (ownIndex > 0) ownValue += `[${ownIndex}]`;
  
      return { value: ownValue, optimized: node.nodeType === Node.DOCUMENT_NODE };
    };
  
    // Helper to get the XPath index for a node.
    window._xPathIndex = function (node) {
      function areNodesSimilar(left, right) {
        if (left === right) return true;
  
        if (
          left.nodeType === Node.ELEMENT_NODE &&
          right.nodeType === Node.ELEMENT_NODE
        )
          return left.localName === right.localName;
  
        if (left.nodeType === right.nodeType) return true;
  
        const leftType =
          left.nodeType === Node.CDATA_SECTION_NODE
            ? Node.TEXT_NODE
            : left.nodeType;
        const rightType =
          right.nodeType === Node.CDATA_SECTION_NODE
            ? Node.TEXT_NODE
            : right.nodeType;
        return leftType === rightType;
      }
  
      const siblings = node.parentNode ? node.parentNode.children : null;
      if (!siblings) return 0;
      let hasSameNamedElements = false;
      for (let i = 0; i < siblings.length; ++i) {
        if (areNodesSimilar(node, siblings[i]) && siblings[i] !== node) {
          hasSameNamedElements = true;
          break;
        }
      }
      if (!hasSameNamedElements) return 0;
      let ownIndex = 1;
      for (let i = 0; i < siblings.length; ++i) {
        if (areNodesSimilar(node, siblings[i])) {
          if (siblings[i] === node) return ownIndex;
          ++ownIndex;
        }
      }
      return -1;
    };
  })();
