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

  function triggerRealClick(el) {
    if (!el) return false;
    el.scrollIntoView({ block: "center", inline: "center" });
    el.focus();
    for (const type of ["pointerdown", "mousedown", "pointerup", "mouseup", "click"]) {
      el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
    }
    if (typeof el.click === "function") el.click();
    return true;
  }

  function dispatchUserInputEvents(el) {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new Event("blur", { bubbles: true }));
  }

  function setFieldValue(selector, value) {
    const el = document.querySelector(selector);
    if (!el) {
      throw new Error("missing field: " + selector);
    }
    el.scrollIntoView({ block: "center", inline: "center" });
    el.focus();
    el.value = value;
    dispatchUserInputEvents(el);
    return el;
  }

  function clickFirstButtonMatching(root, patterns) {
    const scope = root || document;
    const buttons = Array.from(scope.querySelectorAll("button, input[type='button'], input[type='submit']"));
    for (const button of buttons) {
      const text = labelOf(button);
      if (!text || !isVisible(button) || button.disabled) continue;
      if (patterns.some((pattern) => pattern.test(text))) {
        triggerRealClick(button);
        return text;
      }
    }
    return null;
  }

  function findCookieBannerRoot() {
    return Array.from(document.querySelectorAll("div, section, aside, footer, form"))
      .filter((el) => isVisible(el))
      .find((el) =>
        /how to manage cookie preferences|privacy statement|third-party cookies|manage cookies/i.test(
          el.innerText || ""
        )
      );
  }

  function dismissPageBlockers() {
    const actions = [];

    const cookieRoot = findCookieBannerRoot();
    const accepted = clickFirstButtonMatching(cookieRoot, [
      /^accept$/i,
      /^accept all$/i,
      /^accept all cookies$/i,
      /^allow all$/i,
    ]);
    if (accepted) actions.push("cookie:" + accepted);

    const okayed = clickFirstButtonMatching(document, [
      /^ok$/i,
      /^okay$/i,
      /^got it$/i,
      /^close$/i,
    ]);
    if (okayed) actions.push("dialog:" + okayed);

    return {
      timestamp_ms: Date.now(),
      actions,
      cookie_banner_present: !!cookieRoot,
    };
  }

  async function startSignupChallenge(details) {
    const audit = {
      timestamp_ms: Date.now(),
      blockers_before: dismissPageBlockers(),
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
      await sleep(100);
      const emailEl = setFieldValue('input[name="user[email]"]', details.email);
      audit.email_len = emailEl.value.length;
      await sleep(50);
      const passwordEl = setFieldValue('input[name="user[password]"]', details.password);
      audit.password_len = passwordEl.value.length;
      await sleep(50);
      const usernameEl = setFieldValue('input[name="user[login]"]', details.username);
      audit.username_len = usernameEl.value.length;
      await sleep(50);

      const countryInput = document.querySelector('input[name="user_signup[country]"]');
      if (countryInput && details.country) {
        countryInput.value = details.country;
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
      audit.captcha_click_dispatched = triggerRealClick(captchaButton);
      await sleep(150);
      audit.blockers_after = dismissPageBlockers();
    } catch (error) {
      audit.error = String(error && error.message ? error.message : error);
    }

    return JSON.stringify(audit);
  }

  async function finishSignupSubmit() {
    const form = document.querySelector('form[action="/signup?social=false"]');
    if (!form) {
      throw new Error("missing signup form");
    }
    const submitButton = form.querySelector("button.js-octocaptcha-form-submit");
    if (!submitButton) {
      throw new Error("missing final signup submit button");
    }
    triggerRealClick(submitButton);
    return JSON.stringify({
      timestamp_ms: Date.now(),
      submit_label: labelOf(submitButton),
      submit_click_dispatched: true,
    });
  }

  async function submitVerification(details) {
    const audit = {
      timestamp_ms: Date.now(),
      blockers_before: dismissPageBlockers(),
      code_len: 0,
      submit_label: "",
      submit_click_dispatched: false,
      blockers_after: null,
      error: null,
    };

    try {
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

      codeInput.scrollIntoView({ block: "center", inline: "center" });
      codeInput.focus();
      codeInput.value = details.code;
      dispatchUserInputEvents(codeInput);
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
      audit.submit_click_dispatched = triggerRealClick(submitButton);
      await sleep(150);
      audit.blockers_after = dismissPageBlockers();
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
