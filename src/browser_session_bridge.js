// SOURCE: Chrome DevTools Protocol Page.addScriptToEvaluateOnNewDocument
// SOURCE: GitHub live signup DOM inspection (2026-04-11)
(function () {
  "use strict";

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function isVisible(el) {
    if (!el || !el.isConnected) return false;
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
  }

  function labelOf(el) {
    return (
      el?.textContent?.trim() ||
      el?.value?.trim() ||
      el?.getAttribute?.("aria-label")?.trim() ||
      ""
    );
  }

  function setElementValue(el, value) {
    const proto =
      el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement
        ? Object.getPrototypeOf(el)
        : null;
    const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, "value") : null;
    if (descriptor && typeof descriptor.set === "function") {
      descriptor.set.call(el, value);
    } else {
      el.value = value;
    }
  }

  function dispatchKeyboardEvent(el, type, key) {
    const upper = key.length === 1 ? key.toUpperCase() : key;
    const keyCode = upper.length === 1 ? upper.charCodeAt(0) : 0;
    el.dispatchEvent(
      new KeyboardEvent(type, {
        key,
        code: key.length === 1 ? `Key${upper}` : key,
        keyCode,
        which: keyCode,
        charCode: type === "keypress" ? keyCode : 0,
        bubbles: true,
        cancelable: true,
      })
    );
  }

  function dispatchCommitEvents(el) {
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new Event("blur", { bubbles: true }));
  }

  async function humanScrollIntoView(el, stepDelays) {
    if (!el) return false;
    const rect = el.getBoundingClientRect();
    const startY = window.scrollY;
    const targetY = Math.max(0, startY + rect.top - window.innerHeight * 0.35);
    const steps = Array.isArray(stepDelays) && stepDelays.length > 0 ? stepDelays : [0];
    for (let idx = 0; idx < steps.length; idx += 1) {
      const progress = (idx + 1) / steps.length;
      const nextY = Math.round(startY + (targetY - startY) * progress);
      window.scrollTo({ top: nextY, behavior: "instant" });
      await sleep(steps[idx] || 0);
    }
    return true;
  }

  async function triggerHumanClick(el, human) {
    if (!el) return false;
    await humanScrollIntoView(el, human.scroll_step_delays);
    el.focus();
    await sleep(human.pre_click_pause_ms || 0);
    el.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true, cancelable: true, view: window, pointerType: "mouse", isPrimary: true }));
    for (const type of ["pointerdown", "mousedown", "pointerup", "mouseup", "click"]) {
      if (type === "pointerdown") continue;
      if (type === "pointerup") {
        await sleep(human.click_hold_pause_ms || 0);
        el.dispatchEvent(new PointerEvent("pointerup", { bubbles: true, cancelable: true, view: window, pointerType: "mouse", isPrimary: true }));
      }
      el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
    }
    if (typeof el.click === "function") el.click();
    await sleep(human.post_click_pause_ms || 0);
    return true;
  }

  function dispatchUserInputEvents(el) {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new Event("blur", { bubbles: true }));
  }

  async function typeLikeHuman(selector, value, keyDelays, human) {
    const el = document.querySelector(selector);
    if (!el) {
      throw new Error("missing field: " + selector);
    }
    await humanScrollIntoView(el, human.scroll_step_delays);
    el.focus();
    await sleep(human.focus_pause_ms || 0);
    setElementValue(el, "");
    el.dispatchEvent(new Event("input", { bubbles: true }));
    for (let idx = 0; idx < value.length; idx += 1) {
      const ch = value[idx];
      dispatchKeyboardEvent(el, "keydown", ch);
      dispatchKeyboardEvent(el, "keypress", ch);
      setElementValue(el, `${el.value}${ch}`);
      if (typeof InputEvent === "function") {
        el.dispatchEvent(new InputEvent("input", { bubbles: true, data: ch, inputType: "insertText" }));
      } else {
        el.dispatchEvent(new Event("input", { bubbles: true }));
      }
      dispatchKeyboardEvent(el, "keyup", ch);
      await sleep(keyDelays[idx] || 0);
    }
    await sleep(human.between_fields_pause_ms || 0);
    dispatchCommitEvents(el);
    return el;
  }

  function findVisibleButtonMatching(patterns, root) {
    const scope = root || document;
    const buttons = Array.from(scope.querySelectorAll("button, input[type='button'], input[type='submit']"));
    for (const button of buttons) {
      const text = labelOf(button);
      if (!text || !isVisible(button) || button.disabled) continue;
      if (patterns.some((pattern) => pattern.test(text))) {
        return button;
      }
    }
    return null;
  }

  function findCookieAcceptButton() {
    return findVisibleButtonMatching([/^accept$/i, /^accept all$/i, /^accept all cookies$/i, /^allow all$/i]);
  }

  function hasCookieBanner() {
    return !!findCookieAcceptButton();
  }

  function normalizeSignupHuman(human) {
    return {
      email_key_delays: Array.isArray(human?.email_key_delays) ? human.email_key_delays : [],
      password_key_delays: Array.isArray(human?.password_key_delays) ? human.password_key_delays : [],
      username_key_delays: Array.isArray(human?.username_key_delays) ? human.username_key_delays : [],
      scroll_step_delays: Array.isArray(human?.scroll_step_delays) ? human.scroll_step_delays : [0],
      post_dismiss_pause_ms: human?.post_dismiss_pause_ms || 0,
      between_fields_pause_ms: human?.between_fields_pause_ms || 0,
      focus_pause_ms: human?.focus_pause_ms || 0,
      pre_click_pause_ms: human?.pre_click_pause_ms || 0,
      click_hold_pause_ms: human?.click_hold_pause_ms || 0,
      post_click_pause_ms: human?.post_click_pause_ms || 0,
    };
  }

  function normalizeVerificationHuman(human) {
    return {
      code_key_delays: Array.isArray(human?.code_key_delays) ? human.code_key_delays : [],
      scroll_step_delays: Array.isArray(human?.scroll_step_delays) ? human.scroll_step_delays : [0],
      post_dismiss_pause_ms: human?.post_dismiss_pause_ms || 0,
      focus_pause_ms: human?.focus_pause_ms || 0,
      pre_click_pause_ms: human?.pre_click_pause_ms || 0,
      click_hold_pause_ms: human?.click_hold_pause_ms || 0,
      post_click_pause_ms: human?.post_click_pause_ms || 0,
      between_fields_pause_ms: human?.between_fields_pause_ms || 0,
    };
  }

  async function dismissPageBlockersInternal(human) {
    const actions = [];

    const acceptButton = findCookieAcceptButton();
    if (acceptButton) {
      actions.push("cookie:" + labelOf(acceptButton));
      await triggerHumanClick(acceptButton, human);
      await sleep(human.post_dismiss_pause_ms || 0);
    }

    const okayed = findVisibleButtonMatching([
      /^ok$/i,
      /^okay$/i,
      /^got it$/i,
      /^close$/i,
    ]);
    if (okayed) {
      actions.push("dialog:" + labelOf(okayed));
      await triggerHumanClick(okayed, human);
    }

    return {
      timestamp_ms: Date.now(),
      actions,
      cookie_banner_present: hasCookieBanner(),
    };
  }

  async function dismissPageBlockers() {
    return JSON.stringify(
      await dismissPageBlockersInternal({
        scroll_step_delays: [0],
        post_dismiss_pause_ms: 0,
        pre_click_pause_ms: 0,
        click_hold_pause_ms: 0,
        post_click_pause_ms: 0,
      })
    );
  }

  async function startSignupChallenge(details) {
    const human = normalizeSignupHuman(details.human);
    const audit = {
      timestamp_ms: Date.now(),
      blockers_before: null,
      email_len: 0,
      password_len: 0,
      username_len: 0,
      captcha_button_found: false,
      captcha_button_label: "",
      captcha_click_dispatched: false,
      blockers_after: null,
      error: null,
    };

    try {
      audit.blockers_before = await dismissPageBlockersInternal(human);
      const emailEl = await typeLikeHuman('input[name="user[email]"]', details.email, human.email_key_delays, human);
      audit.email_len = emailEl.value.length;
      const passwordEl = await typeLikeHuman('input[name="user[password]"]', details.password, human.password_key_delays, human);
      audit.password_len = passwordEl.value.length;
      const usernameEl = await typeLikeHuman('input[name="user[login]"]', details.username, human.username_key_delays, human);
      audit.username_len = usernameEl.value.length;

      const countryInput = document.querySelector('input[name="user_signup[country]"]');
      if (countryInput && details.country) {
        await humanScrollIntoView(countryInput, human.scroll_step_delays);
        setElementValue(countryInput, details.country);
        dispatchUserInputEvents(countryInput);
      }

      const form = document.querySelector('form[action="/signup?social=false"]');
      if (!form) {
        throw new Error("missing signup form");
      }

      const captchaButton = form.querySelector("button.js-octocaptcha-load-captcha");
      if (!captchaButton) {
        throw new Error("missing captcha trigger button");
      }

      audit.captcha_button_found = true;
      audit.captcha_button_label = labelOf(captchaButton);
      audit.captcha_click_dispatched = await triggerHumanClick(captchaButton, human);
      audit.blockers_after = await dismissPageBlockersInternal(human);
    } catch (error) {
      audit.error = String(error && error.message ? error.message : error);
    }

    return JSON.stringify(audit);
  }

  async function finishSignupSubmit() {
    const human = normalizeSignupHuman({});
    const form = document.querySelector('form[action="/signup?social=false"]');
    if (!form) {
      throw new Error("missing signup form");
    }
    const submitButton = form.querySelector("button.js-octocaptcha-form-submit");
    if (!submitButton) {
      throw new Error("missing final signup submit button");
    }
    await triggerHumanClick(submitButton, human);
    return JSON.stringify({
      timestamp_ms: Date.now(),
      submit_label: labelOf(submitButton),
      submit_click_dispatched: true,
    });
  }

  async function submitVerification(details) {
    const human = normalizeVerificationHuman(details.human);
    const audit = {
      timestamp_ms: Date.now(),
      blockers_before: null,
      code_len: 0,
      submit_label: "",
      submit_click_dispatched: false,
      blockers_after: null,
      error: null,
    };

    try {
      audit.blockers_before = await dismissPageBlockersInternal(human);
      const form =
        document.querySelector('form[action*="account_verifications"]') ||
        document.querySelector('form[action*="verify"]') ||
        document.querySelector("form");
      if (!form) {
        throw new Error("missing verification form");
      }

      const codeInput =
        form.querySelector('input[name="verification_code"]') ||
        form.querySelector('input[inputmode="numeric"]') ||
        form.querySelector('input[type="text"]');
      if (!codeInput) {
        throw new Error("missing verification code input");
      }

      await typeLikeHuman('input[name="verification_code"], input[inputmode="numeric"], input[type="text"]', details.code, human.code_key_delays, human);
      audit.code_len = codeInput.value.length;

      const submitButton =
        form.querySelector('button[type="submit"]') ||
        form.querySelector('input[type="submit"]') ||
        Array.from(form.querySelectorAll("button")).find((btn) =>
          /continue/i.test(btn.textContent || "")
        );
      if (!submitButton) {
        throw new Error("missing verification submit button");
      }

      audit.submit_label = labelOf(submitButton);
      audit.submit_click_dispatched = await triggerHumanClick(submitButton, human);
      audit.blockers_after = await dismissPageBlockersInternal(human);
    } catch (error) {
      audit.error = String(error && error.message ? error.message : error);
    }

    return JSON.stringify(audit);
  }

  window.__ghostBridge = {
    dismissPageBlockers,
    startSignupChallenge,
    finishSignupSubmit,
    submitVerification,
  };
})();
