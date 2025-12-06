(function () {
  const randomId = () => "q" + Math.random().toString(36).slice(2, 9);
  let monacoLoaderPromise = null;
  let monacoReadyPromise = null;

  const escapeHtml = (str) => {
    return (str || "").replace(/[&<>"']/g, (char) => {
      const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
      return map[char] || char;
    });
  };

  const inlineMarkdown = (text) => {
    let t = escapeHtml(text || "");
    t = t.replace(/`([^`]+)`/g, "<code>$1</code>");
    t = t.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    t = t.replace(/\*([^*]+)\*/g, "<em>$1</em>");
    return t;
  };

  const renderMarkdownText = (text) => {
    const lines = (text || "").split(/\n/);
    const parts = [];
    let inList = false;
    lines.forEach((line) => {
      const listMatch = line.match(/^\s*-\s+(.*)/);
      if (listMatch) {
        if (!inList) {
          parts.push("<ul style=\"margin:6px 0 6px 18px; padding:0;\">");
          inList = true;
        }
        parts.push(`<li style="margin:2px 0;">${inlineMarkdown(listMatch[1])}</li>`);
        return;
      }
      if (inList) {
        parts.push("</ul>");
        inList = false;
      }
      if (!line.trim()) {
        parts.push("<br>");
      } else {
        parts.push(`<p style="margin:4px 0;">${inlineMarkdown(line)}</p>`);
      }
    });
    if (inList) parts.push("</ul>");
    return parts.join("");
  };

  function setupExamBuilder() {
    const root = document.querySelector("[data-exam-builder]");
    if (!root) return;
    const list = root.querySelector("[data-question-list]");
    const addBtn = root.querySelector("[data-add-question]");
    const typeSelect = root.querySelector("[data-question-type]");
    const typeButtons = root.querySelectorAll("[data-type-choice]");
    const applyTypeSelection = (value) => {
      if (!typeSelect) return;
      const next = value || "mcq";
      typeSelect.value = next;
      typeButtons.forEach((btn) => {
        const active = btn.dataset.typeChoice === next;
        btn.classList.toggle("btn-primary", active);
      });
    };
    if (typeButtons.length && typeSelect) {
      typeButtons.forEach((btn) => {
        btn.addEventListener("click", () => applyTypeSelection(btn.dataset.typeChoice));
      });
      applyTypeSelection(typeSelect.value || typeButtons[0].dataset.typeChoice);
    }
    const hidden = root.querySelector("#questions_payload");
    const form = root.querySelector("#exam-builder-form");
    if (!list || !addBtn || !typeSelect || !hidden || !form) return;

    const addQuestion = (type, data = {}) => {
      const card = buildQuestionCard(type, data);
      list.appendChild(card);
      syncHidden();
    };

    const syncHidden = () => {
      try {
        hidden.value = JSON.stringify(serializeQuestions(list));
      } catch (err) {
        console.warn("Unable to serialize questions", err);
      }
    };

    addBtn.addEventListener("click", () => {
      addQuestion(typeSelect.value || "mcq");
    });

    list.addEventListener("input", syncHidden);
    list.addEventListener("change", syncHidden);

    list.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) return;
      if (target.dataset.action === "remove-question") {
        target.closest("[data-question-id]")?.remove();
        syncHidden();
      }
      if (target.dataset.action === "add-sample") {
        const card = target.closest("[data-question-id]");
        if (!card) return;
        const modeField = card.querySelector('[data-field="code-mode"]');
        const mode = modeField ? (modeField.value || "script") : "script";
        const selector = mode === "function" ? '[data-sample-list="function"]' : '[data-sample-list="script"]';
        const container = card.querySelector(selector);
        if (container) {
          const row = mode === "function" ? buildFunctionSampleRow() : buildScriptSampleRow();
          container.appendChild(row);
          syncHidden();
        }
      }
      if (target.dataset.action === "remove-sample") {
        target.closest("[data-sample-row]")?.remove();
        syncHidden();
      }
    });

    form.addEventListener("submit", () => {
      syncHidden();
    });

    // bootstrap existing payload
    let initial = [];
    try {
      initial = JSON.parse(hidden.value || "[]");
    } catch (err) {
      console.warn("Bad initial questions payload", err);
    }
    if (initial.length) {
      initial.forEach((q) => addQuestion(q.type || "mcq", q));
    } else {
      addQuestion("mcq");
    }
  }

  function buildQuestionCard(type, data = {}) {
    const card = document.createElement("div");
    card.dataset.questionId = data.id || randomId();
    card.dataset.type = type;
    card.style.border = "1px solid #1f2937";
    card.style.borderRadius = "10px";
    card.style.padding = "16px";

    const header = document.createElement("div");
    header.className = "row";
    header.style.justifyContent = "space-between";
    header.style.alignItems = "center";
    header.innerHTML = `<strong>${type.toUpperCase()}</strong>
      <button type="button" class="btn" data-action="remove-question">Remove</button>`;
    card.appendChild(header);

    const titleLabel = document.createElement("label");
    titleLabel.textContent = "Question title (optional)";
    card.appendChild(titleLabel);
    const titleInput = document.createElement("input");
    titleInput.type = "text";
    titleInput.dataset.field = "title";
    titleInput.placeholder = "e.g., Python Lists";
    titleInput.value = data.title || "";
    card.appendChild(titleInput);

    const promptLabel = document.createElement("label");
    promptLabel.textContent = "Prompt";
    card.appendChild(promptLabel);
    const prompt = document.createElement("textarea");
    prompt.dataset.field = "prompt";
    prompt.rows = 3;
    prompt.value = data.prompt || "";
    card.appendChild(prompt);

    const pointsLabel = document.createElement("label");
    pointsLabel.textContent = "Points";
    card.appendChild(pointsLabel);
    const pointsInput = document.createElement("input");
    pointsInput.type = "number";
    pointsInput.min = "0";
    pointsInput.dataset.field = "points";
    pointsInput.value = data.points != null ? data.points : 1;
    card.appendChild(pointsInput);

    const codeLabel = document.createElement("label");
    codeLabel.textContent = "Code snippet (optional)";
    card.appendChild(codeLabel);
    const codeSnippet = document.createElement("textarea");
    codeSnippet.dataset.field = "code-snippet";
    codeSnippet.rows = 4;
    codeSnippet.placeholder = "e.g., mylist = ['apple', 'banana']";
    codeSnippet.value = data.code_snippet || "";
    card.appendChild(codeSnippet);

    if (type === "mcq") {
      buildChoiceEditor(card, data, "mcq");
    } else if (type === "multi") {
      const hint = document.createElement("p");
      hint.className = "muted";
      hint.textContent = "Students can select multiple answers.";
      card.appendChild(hint);
      buildChoiceEditor(card, data, "multi");
    } else if (type === "text") {
      const placeholderLabel = document.createElement("label");
      placeholderLabel.textContent = "Placeholder";
      card.appendChild(placeholderLabel);
      const placeholder = document.createElement("input");
      placeholder.type = "text";
      placeholder.dataset.field = "placeholder";
      placeholder.value = data.placeholder || "";
      card.appendChild(placeholder);

      const rowsLabel = document.createElement("label");
      rowsLabel.textContent = "Lines";
      card.appendChild(rowsLabel);
      const rows = document.createElement("input");
      rows.type = "number";
      rows.min = "1";
      rows.max = "12";
      rows.dataset.field = "lines";
      rows.value = data.lines || 4;
      card.appendChild(rows);
    } else if (type === "code") {
      const statementLabel = document.createElement("label");
      statementLabel.textContent = "Problem statement";
      card.appendChild(statementLabel);
      const statement = document.createElement("textarea");
      statement.rows = 4;
      statement.dataset.field = "statement";
      statement.placeholder = "Describe what the function/program should do.";
      statement.value = data.statement || "";
      card.appendChild(statement);

      const starterLabel = document.createElement("label");
      starterLabel.textContent = "Starter code";
      card.appendChild(starterLabel);
      const starter = document.createElement("textarea");
      starter.rows = 6;
      starter.dataset.field = "starter";
      starter.placeholder = "# write your solution here";
      starter.value = data.starter || "";
      card.appendChild(starter);

      const modeField = document.createElement("input");
      modeField.type = "hidden";
      modeField.dataset.field = "code-mode";
      modeField.value = data.mode || "script";
      card.appendChild(modeField);

      const modePicker = document.createElement("div");
      modePicker.className = "row";
      modePicker.style.gap = "8px";
      modePicker.style.alignItems = "center";
      modePicker.style.marginTop = "8px";
      modePicker.innerHTML = `
        <span class="muted">Mode:</span>
        <button type="button" class="btn" data-mode-choice="script">Script (stdin/stdout)</button>
        <button type="button" class="btn" data-mode-choice="function">Function (call/return)</button>
      `;
      card.appendChild(modePicker);

      const signatureWrap = document.createElement("div");
      signatureWrap.dataset.codeMode = "function";
      signatureWrap.style.marginTop = "10px";
      const signatureLabel = document.createElement("label");
      signatureLabel.textContent = "Function signature";
      signatureWrap.appendChild(signatureLabel);
      const signatureInput = document.createElement("input");
      signatureInput.type = "text";
      signatureInput.dataset.field = "function-signature";
      signatureInput.placeholder = "def square(n):";
      signatureInput.value = data.function_signature || "";
      signatureWrap.appendChild(signatureInput);
      card.appendChild(signatureWrap);

      const sampleHeader = document.createElement("div");
      sampleHeader.className = "row";
      sampleHeader.style.justifyContent = "space-between";
      sampleHeader.style.alignItems = "center";
      sampleHeader.style.marginTop = "10px";
      sampleHeader.innerHTML = `<strong>Samples</strong>
        <button type="button" class="btn" data-action="add-sample">Add sample</button>`;
      card.appendChild(sampleHeader);

      const sampleHelper = document.createElement("p");
      sampleHelper.className = "muted";
      sampleHelper.style.marginTop = "-4px";
      sampleHelper.textContent = "Provide input/output pairs for script mode, or function calls and expected returns for function mode.";
      card.appendChild(sampleHelper);

      const scriptSampleList = document.createElement("div");
      scriptSampleList.dataset.sampleList = "script";
      scriptSampleList.style.display = "flex";
      scriptSampleList.style.flexDirection = "column";
      scriptSampleList.style.gap = "10px";
      card.appendChild(scriptSampleList);

      const functionSampleList = document.createElement("div");
      functionSampleList.dataset.sampleList = "function";
      functionSampleList.style.display = "flex";
      functionSampleList.style.flexDirection = "column";
      functionSampleList.style.gap = "10px";
      card.appendChild(functionSampleList);

      const samples = Array.isArray(data.samples) && data.samples.length ? data.samples : [{}];
      samples.forEach((sample) => {
        if (sample.call) {
          functionSampleList.appendChild(buildFunctionSampleRow(sample));
        } else {
          scriptSampleList.appendChild(buildScriptSampleRow(sample));
        }
      });
      if (!scriptSampleList.children.length) {
        scriptSampleList.appendChild(buildScriptSampleRow());
      }
      if (!functionSampleList.children.length) {
        functionSampleList.appendChild(buildFunctionSampleRow());
      }

      const updateModeUI = () => {
        const mode = modeField.value || "script";
        scriptSampleList.style.display = mode === "script" ? "flex" : "none";
        functionSampleList.style.display = mode === "function" ? "flex" : "none";
        signatureWrap.style.display = mode === "function" ? "block" : "none";
        modePicker.querySelectorAll("button[data-mode-choice]").forEach((btn) => {
          const active = btn.dataset.modeChoice === mode;
          btn.classList.toggle("btn-primary", active);
        });
      };
      modePicker.querySelectorAll("button[data-mode-choice]").forEach((btn) => {
        btn.addEventListener("click", () => {
          modeField.value = btn.dataset.modeChoice;
          updateModeUI();
        });
      });
      updateModeUI();
    } else if (type === "tokens") {
      const info = document.createElement("p");
      info.className = "muted";
      info.textContent = "Use [[blank]] markers in the expression where you want students to drop tokens.";
      card.appendChild(info);

      const templateLabel = document.createElement("label");
      templateLabel.textContent = "Expression template";
      card.appendChild(templateLabel);
      const templateField = document.createElement("textarea");
      templateField.rows = 3;
      templateField.dataset.field = "tokens-template";
      templateField.placeholder = "[[blank]]([[blank]](myvar))";
      templateField.value = data.template || "";
      card.appendChild(templateField);

      const correctLabel = document.createElement("label");
      correctLabel.textContent = "Correct tokens (comma separated, in order)";
      card.appendChild(correctLabel);
      const correctInput = document.createElement("input");
      correctInput.type = "text";
      correctInput.dataset.field = "tokens-correct";
      const correctVal = Array.isArray(data.correct_tokens) ? data.correct_tokens.join(", ") : (data.correct_tokens || "");
      correctInput.value = correctVal;
      card.appendChild(correctInput);

      const distractorLabel = document.createElement("label");
      distractorLabel.textContent = "Distractor tokens (comma separated)";
      card.appendChild(distractorLabel);
      const distractorInput = document.createElement("input");
      distractorInput.type = "text";
      distractorInput.dataset.field = "tokens-distractors";
      const distVal = Array.isArray(data.distractor_tokens) ? data.distractor_tokens.join(", ") : (data.distractor_tokens || "");
      distractorInput.value = distVal;
      card.appendChild(distractorInput);
    } else if (type === "fill") {
      const info = document.createElement("p");
      info.className = "muted";
      info.textContent = "Use [[blank]] markers where students type their answers. Provide the correct values in order.";
      card.appendChild(info);

      const templateLabel = document.createElement("label");
      templateLabel.textContent = "Expression template";
      card.appendChild(templateLabel);
      const templateField = document.createElement("textarea");
      templateField.rows = 3;
      templateField.dataset.field = "fill-template";
      templateField.placeholder = 'carname = "[[blank]]"';
      templateField.value = data.template || "";
      card.appendChild(templateField);

      const answersLabel = document.createElement("label");
      answersLabel.textContent = "Correct values (comma separated, in order)";
      card.appendChild(answersLabel);
      const answersInput = document.createElement("input");
      answersInput.type = "text";
      answersInput.dataset.field = "fill-answers";
      const answersVal = Array.isArray(data.answers) ? data.answers.join(", ") : (data.answers || "");
      answersInput.value = answersVal;
      card.appendChild(answersInput);

      const caseWrap = document.createElement("label");
      caseWrap.style.display = "flex";
      caseWrap.style.alignItems = "center";
      caseWrap.style.gap = "8px";
      caseWrap.style.marginTop = "8px";
      const caseInput = document.createElement("input");
      caseInput.type = "checkbox";
      caseInput.dataset.field = "fill-case-sensitive";
      caseInput.checked = !!data.case_sensitive;
      caseWrap.appendChild(caseInput);
      caseWrap.append("Case sensitive?");
      card.appendChild(caseWrap);
    }

    return card;
  }

  function buildChoiceEditor(card, data = {}, kind = "mcq") {
    const wrapper = document.createElement("div");
    wrapper.style.display = "flex";
    wrapper.style.flexDirection = "column";
    wrapper.style.gap = "10px";
    card.appendChild(wrapper);

    const list = document.createElement("div");
    list.dataset.choiceList = "1";
    list.style.display = "flex";
    list.style.flexDirection = "column";
    list.style.gap = "10px";
    wrapper.appendChild(list);

    const existing = Array.isArray(data.options)
      ? data.options
      : typeof data.options === "string"
        ? data.options.split("\n")
        : [];

    const addRow = (value = "") => {
      const row = document.createElement("div");
      row.style.display = "flex";
      row.style.gap = "8px";
      row.style.alignItems = "stretch";

      const textarea = document.createElement("textarea");
      textarea.dataset.choiceOption = "1";
      textarea.rows = 2;
      textarea.placeholder = "Option text";
      textarea.value = value;
      textarea.style.flex = "1";
      row.appendChild(textarea);

      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn";
      remove.textContent = "Remove";
      remove.addEventListener("click", () => {
        row.remove();
      });
      row.appendChild(remove);

      list.appendChild(row);
    };

    if (existing.length) {
      existing.forEach((val) => addRow(val));
    } else {
      addRow("Option 1");
      addRow("Option 2");
    }

    const addBtn = document.createElement("button");
    addBtn.type = "button";
    addBtn.className = "btn";
    addBtn.textContent = "Add option";
    addBtn.addEventListener("click", () => addRow(""));
    wrapper.appendChild(addBtn);

    const correctLabel = document.createElement("label");
    correctLabel.textContent = kind === "multi"
      ? "Correct option indexes (comma separated, 0-based)"
      : "Correct option index (0-based)";
    wrapper.appendChild(correctLabel);
    const correctInput = document.createElement("input");
    correctInput.type = "text";
    correctInput.dataset.field = "choices-correct";
    const existingCorrect = Array.isArray(data.correct_indices)
      ? data.correct_indices.join(", ")
      : (data.correct_indices || "");
    correctInput.value = existingCorrect;
    wrapper.appendChild(correctInput);
  }

  function buildScriptSampleRow(sample = {}) {
    const wrapper = document.createElement("div");
    wrapper.dataset.sampleRow = "1";
    wrapper.style.border = "1px dashed #334155";
    wrapper.style.borderRadius = "8px";
    wrapper.style.padding = "10px";

    const nameLabel = document.createElement("label");
    nameLabel.textContent = "Name";
    wrapper.appendChild(nameLabel);

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.dataset.field = "sample-name";
    nameInput.value = sample.name || "";
    wrapper.appendChild(nameInput);

    const inputLabel = document.createElement("label");
    inputLabel.textContent = "Input";
    wrapper.appendChild(inputLabel);

    const inputField = document.createElement("textarea");
    inputField.rows = 3;
    inputField.dataset.field = "sample-input";
    inputField.value = sample.input || "";
    wrapper.appendChild(inputField);

    const outputLabel = document.createElement("label");
    outputLabel.textContent = "Expected output";
    wrapper.appendChild(outputLabel);

    const outputField = document.createElement("textarea");
    outputField.rows = 3;
    outputField.dataset.field = "sample-output";
    outputField.value = sample.output || "";
    wrapper.appendChild(outputField);

    const hiddenLabel = document.createElement("label");
    hiddenLabel.style.display = "flex";
    hiddenLabel.style.alignItems = "center";
    hiddenLabel.style.gap = "6px";
    const hiddenInput = document.createElement("input");
    hiddenInput.type = "checkbox";
    hiddenInput.dataset.field = "sample-hidden";
    hiddenInput.checked = !!sample.hidden;
    hiddenLabel.appendChild(hiddenInput);
    hiddenLabel.append("Hidden?");
    wrapper.appendChild(hiddenLabel);

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn";
    removeBtn.dataset.action = "remove-sample";
    removeBtn.style.marginTop = "6px";
    removeBtn.textContent = "Remove sample";
    wrapper.appendChild(removeBtn);

    return wrapper;
  }

  function buildFunctionSampleRow(sample = {}) {
    const wrapper = document.createElement("div");
    wrapper.dataset.sampleRow = "1";
    wrapper.style.border = "1px dashed #334155";
    wrapper.style.borderRadius = "8px";
    wrapper.style.padding = "10px";

    const nameLabel = document.createElement("label");
    nameLabel.textContent = "Name";
    wrapper.appendChild(nameLabel);

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.dataset.field = "sample-name";
    nameInput.value = sample.name || "";
    wrapper.appendChild(nameInput);

    const callLabel = document.createElement("label");
    callLabel.textContent = "Function call";
    wrapper.appendChild(callLabel);

    const callInput = document.createElement("input");
    callInput.type = "text";
    callInput.dataset.field = "sample-call";
    callInput.placeholder = "square(5)";
    callInput.value = sample.call || sample.input || "";
    wrapper.appendChild(callInput);

    const expectedLabel = document.createElement("label");
    expectedLabel.textContent = "Expected return";
    wrapper.appendChild(expectedLabel);

    const expectedInput = document.createElement("input");
    expectedInput.type = "text";
    expectedInput.dataset.field = "sample-expected";
    expectedInput.placeholder = "25";
    expectedInput.value = sample.expected || sample.output || "";
    wrapper.appendChild(expectedInput);

    const hiddenLabel = document.createElement("label");
    hiddenLabel.style.display = "flex";
    hiddenLabel.style.alignItems = "center";
    hiddenLabel.style.gap = "6px";
    const hiddenInput = document.createElement("input");
    hiddenInput.type = "checkbox";
    hiddenInput.dataset.field = "sample-hidden";
    hiddenInput.checked = !!sample.hidden;
    hiddenLabel.appendChild(hiddenInput);
    hiddenLabel.append("Hidden?");
    wrapper.appendChild(hiddenLabel);

    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn";
    removeBtn.dataset.action = "remove-sample";
    removeBtn.style.marginTop = "6px";
    removeBtn.textContent = "Remove sample";
    wrapper.appendChild(removeBtn);

    return wrapper;
  }

  function serializeQuestions(list) {
    if (!list) return [];
    return Array.from(list.querySelectorAll("[data-question-id]")).map((card) => {
      const type = card.dataset.type;
      const id = card.dataset.questionId || randomId();
      const prompt = getFieldValue(card, "prompt");
      const payload = { id, type, prompt };
      const title = getFieldValue(card, "title");
      if (title) payload.title = title;
      const snippet = getFieldValue(card, "code-snippet");
      if (snippet) payload.code_snippet = snippet;
      const pointsRaw = parseInt(getFieldValue(card, "points"), 10);
      payload.points = Number.isFinite(pointsRaw) ? Math.max(0, pointsRaw) : 1;
      if (type === "mcq" || type === "multi") {
        const rows = card.querySelectorAll("[data-choice-option]");
        payload.options = Array.from(rows).map((el) => el.value.trim()).filter(Boolean);
        const correctRaw = getFieldValue(card, "choices-correct");
        if (correctRaw) {
          const indices = correctRaw
            .split(/[,\\s]+/)
            .map((val) => parseInt(val, 10))
            .filter((num) => Number.isFinite(num));
          if (indices.length) payload.correct_indices = indices;
        }
      } else if (type === "text") {
        payload.placeholder = getFieldValue(card, "placeholder");
        payload.lines = getFieldValue(card, "lines") || 4;
      } else if (type === "code") {
        const mode = getFieldValue(card, "code-mode") || "script";
        payload.mode = mode;
        payload.statement = getFieldValue(card, "statement");
        payload.starter = getFieldValue(card, "starter");
        if (mode === "function") {
          payload.function_signature = getFieldValue(card, "function-signature");
          const rows = card.querySelectorAll('[data-sample-list="function"] [data-sample-row]');
          payload.samples = Array.from(rows).map((row) => ({
            name: getFieldValue(row, "sample-name"),
            call: getFieldValue(row, "sample-call"),
            expected: getFieldValue(row, "sample-expected"),
            hidden: !!row.querySelector('[data-field="sample-hidden"]')?.checked,
          }));
        } else {
          const rows = card.querySelectorAll('[data-sample-list="script"] [data-sample-row]');
          payload.samples = Array.from(rows).map((row) => ({
            name: getFieldValue(row, "sample-name"),
            input: getFieldValue(row, "sample-input"),
            output: getFieldValue(row, "sample-output"),
            hidden: !!row.querySelector('[data-field="sample-hidden"]')?.checked,
          }));
        }
      } else if (type === "tokens") {
        payload.template = getFieldValue(card, "tokens-template");
        payload.correct_tokens = getFieldValue(card, "tokens-correct");
        payload.distractor_tokens = getFieldValue(card, "tokens-distractors");
      } else if (type === "fill") {
        payload.template = getFieldValue(card, "fill-template");
        payload.answers = getFieldValue(card, "fill-answers");
        payload.case_sensitive = !!card.querySelector('[data-field="fill-case-sensitive"]')?.checked;
      }
      return payload;
    });
  }

  function getFieldValue(container, fieldName) {
    const el = container.querySelector(`[data-field="${fieldName}"]`);
    return el ? el.value : "";
  }

  // ---------------------------
  // Exam runner + code samples
  // ---------------------------
  function setupExamRunner() {
    const root = document.querySelector("[data-exam-take]");
    if (!root) return;
    const buttons = root.querySelectorAll("[data-run-samples]");
    const customButtons = root.querySelectorAll("[data-run-custom]");
    if (!buttons.length && !customButtons.length) return;
    let pyodidePromise = null;

    const ensurePyodide = async () => {
      if (!window.loadPyodide) {
        throw new Error("Pyodide script not loaded");
      }
      if (!pyodidePromise) {
        pyodidePromise = loadPyodide({ indexURL: "https://cdn.jsdelivr.net/pyodide/v0.24.1/full/" });
      }
      return pyodidePromise;
    };

    const logUrl = root.dataset.runLogUrl;
    const csrf = root.dataset.csrf;

    const postLog = async (questionId, samples) => {
      if (!logUrl || !csrf) return;
      try {
        await fetch(logUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF": csrf,
          },
          body: JSON.stringify({ question_id: questionId, samples }),
        });
      } catch (err) {
        console.warn("Unable to log run", err);
      }
    };

    const renderResults = (container, results, summaryEl) => {
      const safeResults = Array.isArray(results) ? results : [];
      container.innerHTML = "";
      const total = safeResults.length;
      const passed = safeResults.filter((s) => s.status === "passed").length;
      if (summaryEl) {
        let badge = `${passed}/${total} passed`;
        let color = "#38bdf8";
        if (total === 0) {
          badge = "Not run";
          color = "#94a3b8";
        } else if (passed === total) {
          color = "#4ade80";
          badge = "All tests passed";
        } else if (passed === 0) {
          color = "#f87171";
        } else {
          color = "#fbbf24";
        }
        summaryEl.textContent = badge;
        summaryEl.style.color = color;
        summaryEl.style.borderColor = "#334155";
      }
      if (!total) {
        container.textContent = "No results to show.";
        return;
      }

      const summary = document.createElement("div");
      summary.className = "test-summary";
      summary.innerHTML = `<strong>Summary:</strong> ${passed} / ${total} tests passed`;
      summary.style.padding = "8px";
      summary.style.border = "1px solid #1f2937";
      summary.style.borderRadius = "8px";
      summary.style.marginBottom = "8px";
      summary.style.background = "#0f172a";
      container.appendChild(summary);

      const buildDiff = (expected, output) => {
        const diffWrap = document.createElement("div");
        diffWrap.style.marginTop = "6px";
        const expLines = (expected || "").split("\n");
        const outLines = (output || "").split("\n");
        const rows = Math.max(expLines.length, outLines.length);
        const list = document.createElement("div");
        list.style.border = "1px solid #1f2937";
        list.style.borderRadius = "8px";
        list.style.overflow = "hidden";
        for (let i = 0; i < rows; i += 1) {
          const expLine = expLines[i] || "";
          const outLine = outLines[i] || "";
          const match = expLine === outLine;
          const row = document.createElement("div");
          row.style.display = "grid";
          row.style.gridTemplateColumns = "1fr 1fr";
          row.style.gap = "1px";
          row.style.background = "#0b1220";
          const expCell = document.createElement("div");
          expCell.style.padding = "6px";
          expCell.style.background = match ? "#0b1220" : "#1f2937";
          expCell.style.fontFamily = "SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace";
          expCell.style.whiteSpace = "pre-wrap";
          expCell.innerHTML = escapeHtml(expLine || "");
          const outCell = document.createElement("div");
          outCell.style.padding = "6px";
          outCell.style.background = match ? "#0b1220" : "#1f2937";
          outCell.style.fontFamily = "SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace";
          outCell.style.whiteSpace = "pre-wrap";
          outCell.innerHTML = escapeHtml(outLine || "");
          row.appendChild(expCell);
          row.appendChild(outCell);
          list.appendChild(row);
        }
        diffWrap.appendChild(list);
        return diffWrap;
      };

      safeResults.forEach((sample) => {
        const status = sample.status || "unknown";
        const statusColor = {
          passed: "#4ade80",
          mismatch: "#fbbf24",
          timeout: "#fbbf24",
          error: "#f87171",
          unknown: "#38bdf8",
        }[status] || "#38bdf8";

        const card = document.createElement("div");
        card.className = "test-case";
        card.style.border = "1px solid #1f2937";
        card.style.borderRadius = "10px";
        card.style.padding = "10px";
        card.style.marginBottom = "8px";
        card.style.background = "#0f172a";

        const header = document.createElement("div");
        header.style.display = "flex";
        header.style.justifyContent = "space-between";
        header.style.alignItems = "center";
        header.style.gap = "10px";
        const left = document.createElement("div");
        left.innerHTML = `<strong>${escapeHtml(sample.name || "Sample")}</strong>`;
        const badge = document.createElement("span");
        badge.textContent = status;
        badge.style.color = statusColor;
        badge.style.border = `1px solid ${statusColor}`;
        badge.style.borderRadius = "12px";
        badge.style.padding = "4px 8px";
        badge.style.fontSize = "0.85rem";
        header.appendChild(left);
        header.appendChild(badge);
        card.appendChild(header);

        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.textContent = "Details";
        toggle.className = "btn";
        toggle.style.marginTop = "8px";

        const details = document.createElement("div");
        details.style.marginTop = "10px";
        details.style.display = "none";

        toggle.addEventListener("click", () => {
          const open = details.style.display === "block";
          details.style.display = open ? "none" : "block";
          toggle.textContent = open ? "Details" : "Hide details";
        });

        const labelInput = sample.mode === "function" ? "Call" : "Input";
        const inputBlock = document.createElement("div");
        inputBlock.innerHTML = `
          <div class="muted">${labelInput}</div>
          <pre style="white-space:pre-wrap; background:#0b1220; padding:8px; border-radius:8px; font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">${escapeHtml(sample.input || "")}</pre>
        `;

        const outputBlock = document.createElement("div");
        outputBlock.style.marginTop = "8px";
        outputBlock.innerHTML = `
          <div class="muted">Your output</div>
          <pre style="white-space:pre-wrap; background:#0b1220; padding:8px; border-radius:8px; font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">${escapeHtml(sample.output || "")}</pre>
        `;

        const expectedBlock = document.createElement("div");
        expectedBlock.style.marginTop = "8px";
        expectedBlock.innerHTML = `
          <div class="muted">Expected output</div>
          <pre style="white-space:pre-wrap; background:#0b1220; padding:8px; border-radius:8px; font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">${escapeHtml(sample.expected || "")}</pre>
        `;

        details.appendChild(inputBlock);
        details.appendChild(outputBlock);
        details.appendChild(expectedBlock);

        if (sample.expected && (sample.output || sample.output === "")) {
          const diffWrap = buildDiff(sample.expected, sample.output);
          const diffLabel = document.createElement("div");
          diffLabel.className = "muted";
          diffLabel.style.marginTop = "8px";
          diffLabel.textContent = "Diff (expected vs your output)";
          details.appendChild(diffLabel);
          details.appendChild(diffWrap);
        }

        if (sample.error) {
          const errLabel = document.createElement("div");
          errLabel.className = "muted";
          errLabel.style.marginTop = "8px";
          errLabel.textContent = "Error details";
          const errBlock = document.createElement("pre");
          errBlock.textContent = sample.error;
          errBlock.style.background = "#1f2937";
          errBlock.style.padding = "8px";
          errBlock.style.borderRadius = "8px";
          errBlock.style.whiteSpace = "pre-wrap";
          details.appendChild(errLabel);
          details.appendChild(errBlock);
        }

        card.appendChild(toggle);
        card.appendChild(details);
        container.appendChild(card);
      });
    };

    const executeSamples = async (triggerBtn, samples, modeOverride, codeOverride) => {
      const pyodide = await ensurePyodide();
      const codeInput = root.querySelector(`[data-code-input="${triggerBtn.dataset.question}"]`);
      const codeValue = codeOverride !== undefined ? codeOverride : (codeInput ? codeInput.value : "");
      pyodide.globals.set("runner_code", codeValue);
      pyodide.globals.set("runner_samples", samples);
      pyodide.globals.set("runner_mode", modeOverride || triggerBtn.getAttribute("data-mode") || "script");
      const output = await pyodide.runPythonAsync(`
import io, sys, traceback, json, builtins

code = str(runner_code)
samples = runner_samples.to_py()
mode = str(runner_mode)

# ---- Hard limits (tune as you like) ----
MAX_SETUP_OPS = 50_000    # for exec(code) in function mode
MAX_RUN_OPS   = 200_000   # for each sample run

class TimeLimitExceeded(Exception):
    pass

def _make_tracer(limit):
    counter = {"n": 0}
    def tracefunc(frame, event, arg):
        if event == "line":
            counter["n"] += 1
            if counter["n"] > limit:
                raise TimeLimitExceeded("Execution time limit exceeded.")
        return tracefunc
    return tracefunc

def _safe_exec(src, glb, lcl, limit):
    tracer = _make_tracer(limit)
    sys.settrace(tracer)
    try:
        exec(src, glb, lcl)
    finally:
        sys.settrace(None)

def _safe_eval(expr, glb, lcl, limit):
    tracer = _make_tracer(limit)
    sys.settrace(tracer)
    try:
        return eval(expr, glb, lcl)
    finally:
        sys.settrace(None)

results = []
namespace = {}
setup_error = None

# ---------- Setup for function mode ----------
if mode == "function":
    try:
        _safe_exec(code, namespace, namespace, MAX_SETUP_OPS)
    except TimeLimitExceeded:
        setup_error = "Setup time limit exceeded."
    except Exception:
        setup_error = traceback.format_exc()

# ---------- Run samples ----------
for sample in samples:
    name = sample.get("name") or "Sample"

    if mode == "function":
        call_expr = (sample.get("call") or sample.get("input") or "").strip()
        expected_output = (sample.get("expected") or sample.get("output") or "").strip()

        status = "passed"
        error_text = ""
        output_value = ""

        if not call_expr:
            status = "error"
            error_text = "Missing call expression."
        elif setup_error:
            status = "error"
            error_text = setup_error
        else:
            stdout = io.StringIO()
            original_stdout = sys.stdout
            sys.stdout = stdout
            try:
                try:
                    result = _safe_eval(call_expr, namespace, namespace, MAX_RUN_OPS)
                    output_value = repr(result)
                except TimeLimitExceeded:
                    status = "timeout"
                    error_text = "Execution time limit exceeded."
                except Exception:
                    status = "error"
                    error_text = traceback.format_exc()
            finally:
                sys.stdout = original_stdout

        if status == "passed" and expected_output.strip() and output_value.strip() != expected_output.strip():
            status = "mismatch"

        results.append({
            "name": name,
            "status": status,
            "input": call_expr,
            "output": output_value,
            "expected": expected_output,
            "error": error_text,
            "mode": "function",
        })

    else:
        # script / stdin mode
        sample_input = sample.get("input") or ""
        expected_output = sample.get("expected") or sample.get("output") or ""

        stdin = io.StringIO(sample_input)
        stdout = io.StringIO()
        original_stdout = sys.stdout
        original_stdin = sys.stdin
        original_input = builtins.input

        sys.stdout = stdout
        sys.stdin = stdin
        builtins.input = lambda prompt=None: stdin.readline().rstrip("\\n")

        status = "passed"
        error_text = ""

        try:
            try:
                _safe_exec(code, {"__name__": "__main__"}, {}, MAX_RUN_OPS)
            except TimeLimitExceeded:
                status = "timeout"
                error_text = "Execution time limit exceeded."
            except Exception:
                status = "error"
                error_text = traceback.format_exc()
        finally:
            sys.stdout = original_stdout
            sys.stdin = original_stdin
            builtins.input = original_input

        output_value = stdout.getvalue()

        if status == "passed" and expected_output.strip() and output_value.strip() != expected_output.strip():
            status = "mismatch"

        results.append({
            "name": name,
            "status": status,
            "input": sample_input,
            "output": output_value,
            "expected": expected_output,
            "error": error_text,
            "mode": "script",
        })

json.dumps(results)
      `);
      pyodide.globals.delete("runner_code");
      pyodide.globals.delete("runner_samples");
      pyodide.globals.delete("runner_mode");
      return JSON.parse(output);
    };

    buttons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        const samplesRaw = btn.getAttribute("data-samples") || "[]";
        let samples = [];
        try {
          samples = JSON.parse(samplesRaw);
        } catch (err) {
          console.warn("Bad sample payload", err);
        }
        const questionId = btn.dataset.question;
        const codeArea = root.querySelector(`[data-code-input="${questionId}"]`);
        const resultsContainer = root.querySelector(`[data-results="${questionId}"]`);
        const summaryEl = root.querySelector(`[data-sample-summary="${questionId}"]`);
        if (!codeArea || !resultsContainer) return;
        if (!samples.length) {
          resultsContainer.textContent = "No samples configured for this question.";
          return;
        }
        const originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Running...";
        resultsContainer.textContent = "Preparing Pyodide...";
        try {
          const parsed = await executeSamples(btn, samples, btn.getAttribute("data-mode") || "script", codeArea.value);
          renderResults(resultsContainer, parsed, summaryEl);
          postLog(questionId, parsed);
        } catch (err) {
          console.error(err);
          resultsContainer.textContent = `Unable to run samples: ${err.message || err}`;
          if (summaryEl) {
            summaryEl.textContent = "Run failed";
            summaryEl.style.color = "#f87171";
          }
        } finally {
          btn.disabled = false;
          btn.textContent = originalText;
        }
      });
    });

    customButtons.forEach((btn) => {
      btn.addEventListener("click", async () => {
        const questionId = btn.dataset.question;
        const mode = btn.dataset.mode || "script";
        const container = root.querySelector(`[data-custom-results="${questionId}"]`);
        const codeArea = root.querySelector(`[data-code-input="${questionId}"]`);
        const summaryEl = root.querySelector(`[data-custom-summary="${questionId}"]`);
        if (!questionId || !container) return;
        let samples = [];
        if (mode === "function") {
          const callInput = root.querySelector(`[data-custom-call="${questionId}"]`);
          const callExpr = callInput ? callInput.value.trim() : "";
          if (!callExpr) {
            container.textContent = "Enter a function call to run.";
            return;
          }
          samples = [{ name: "Custom run", call: callExpr, input: callExpr, expected: "" }];
        } else {
          const stdinField = root.querySelector(`[data-custom-stdin="${questionId}"]`);
          const stdinValue = stdinField ? stdinField.value : "";
          samples = [{ name: "Custom run", input: stdinValue, expected: "" }];
        }
        container.textContent = "Running custom input...";
        try {
          const results = await executeSamples(btn, samples, mode, codeArea ? codeArea.value : undefined);
          renderResults(container, results, summaryEl);
        } catch (err) {
          container.textContent = `Unable to run: ${err.message || err}`;
          if (summaryEl) {
            summaryEl.textContent = "Run failed";
            summaryEl.style.color = "#f87171";
          }
        }
      });
    });
  }

  function setupCodeEditors() {
    const codeAreas = Array.from(document.querySelectorAll("textarea[data-code-input]"));
    if (!codeAreas.length) return;
    const MONACO_BASE = "https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs";
    const MONACO_LOADER = `${MONACO_BASE}/loader.min.js`;

    const ensureLoader = () => {
      if (window.require && window.require.config) {
        return Promise.resolve();
      }
      if (!monacoLoaderPromise) {
        monacoLoaderPromise = new Promise((resolve, reject) => {
          const script = document.createElement("script");
          script.src = MONACO_LOADER;
          script.async = true;
          script.crossOrigin = "anonymous";
          script.onload = () => resolve();
          script.onerror = () => reject(new Error("Unable to load Monaco loader"));
          document.head.appendChild(script);
        });
      }
      return monacoLoaderPromise;
    };

    const ensureMonaco = () => {
      if (window.monaco) {
        return Promise.resolve(window.monaco);
      }
      if (!monacoReadyPromise) {
        monacoReadyPromise = ensureLoader().then(() => new Promise((resolve, reject) => {
          if (!window.require || !window.require.config) {
            reject(new Error("Monaco loader unavailable"));
            return;
          }
          const workerSrc = `${MONACO_BASE}/base/worker/workerMain.js`;
          window.MonacoEnvironment = window.MonacoEnvironment || {};
          window.MonacoEnvironment.getWorkerUrl = () => {
            const workerScript = [
              `self.MonacoEnvironment = { baseUrl: '${MONACO_BASE}/' };`,
              `importScripts('${workerSrc}');`,
            ].join("\n");
            return `data:text/javascript;charset=utf-8,${encodeURIComponent(workerScript)}`;
          };
          window.require.config({ paths: { vs: MONACO_BASE } });
          window.require(["vs/editor/editor.main"], () => resolve(window.monaco), (error) => reject(error));
        }));
      }
      return monacoReadyPromise;
    };

    const disableCopyPaste = (editor, monaco) => {
      editor.onKeyDown((evt) => {
        if (!(evt.ctrlKey || evt.metaKey)) return;
        if ([monaco.KeyCode.KEY_V, monaco.KeyCode.KEY_C, monaco.KeyCode.KEY_X].includes(evt.keyCode)) {
          evt.preventDefault();
        }
      });
      const domNode = editor.getDomNode();
      if (!domNode) return;
      const block = (event) => {
        event.preventDefault();
        event.stopPropagation();
      };
      ["paste", "copy", "cut"].forEach((type) => domNode.addEventListener(type, block));
    };

    ensureMonaco()
      .then((monaco) => {
        codeAreas.forEach((area) => {
          if (area.dataset.monacoAttached === "1") return;
          area.dataset.monacoAttached = "1";
          const wrapper = document.createElement("div");
          wrapper.className = "code-editor-shell";
          wrapper.style.width = "100%";
          const host = document.createElement("div");
          host.className = "code-editor-host";
          const rowsAttr = parseInt(area.getAttribute("rows") || "12", 10);
          const hostHeight = Math.max(200, rowsAttr * 20);
          host.style.height = `${hostHeight}px`;
          wrapper.appendChild(host);
          area.parentNode.insertBefore(wrapper, area.nextSibling);
          const language = (area.dataset.codeLanguage || "python").toLowerCase();
          const readOnly = area.disabled || area.hasAttribute("readonly");
          const editor = monaco.editor.create(host, {
            value: area.value || "",
            language,
            theme: "vs-dark",
            readOnly,
            automaticLayout: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
          });
          disableCopyPaste(editor, monaco);
          area._monacoEditor = editor;
          const syncValue = () => {
            area.value = editor.getValue();
          };
          editor.onDidChangeModelContent(syncValue);
          syncValue();
          area.style.display = "none";
        });
      })
      .catch((err) => {
        console.warn("Unable to initialize Monaco editor", err);
      });
  }

  function setupTokenQuestions() {
    document.querySelectorAll("[data-token-question]").forEach((container) => {
      const slots = Array.from(container.querySelectorAll("[data-token-slot]"));
      if (!slots.length) return;
      const tokens = Array.from(container.querySelectorAll("[data-token-option]"));
      const hidden = container.querySelector("[data-token-answer]");
      const assignments = Array(slots.length).fill(null);
      let values = Array(slots.length).fill("");
      if (hidden && hidden.value) {
        const parts = hidden.value.split("||");
        parts.forEach((val, idx) => {
          if (idx < values.length) values[idx] = val;
        });
      }

      let activeIndex = values.findIndex((v) => !v);
      const setActive = (idx) => {
        activeIndex = typeof idx === "number" ? idx : -1;
        slots.forEach((slot, i) => {
          slot.classList.toggle("active", activeIndex === i && !values[i]);
        });
      };

      const updateHidden = () => {
        if (hidden) hidden.value = values.join("||");
      };

      const refreshSlots = () => {
        slots.forEach((slot, idx) => {
          slot.textContent = values[idx] || slot.dataset.placeholder || "_____";
        });
        updateHidden();
      };

      const claimButton = (val) => {
        const btn = tokens.find((b) => !b.disabled && (b.dataset.tokenValue || b.textContent.trim()) === val);
        if (btn) {
          btn.disabled = true;
          btn.classList.add("disabled");
          return btn;
        }
        return null;
      };

      values.forEach((val, idx) => {
        if (!val) return;
        assignments[idx] = claimButton(val);
      });
      refreshSlots();
      if (activeIndex === -1) {
        const next = values.findIndex((v) => !v);
        setActive(next);
      } else {
        setActive(activeIndex);
      }

      const clearSlot = (idx) => {
        if (!values[idx]) {
          setActive(idx);
          return;
        }
        const btn = assignments[idx];
        if (btn) {
          btn.disabled = false;
          btn.classList.remove("disabled");
        }
        assignments[idx] = null;
        values[idx] = "";
        refreshSlots();
        setActive(idx);
      };

      const assignValue = (btn) => {
        const value = btn.dataset.tokenValue || btn.textContent.trim();
        let target = activeIndex;
        if (target === -1) target = values.findIndex((v) => !v);
        if (target === -1) return;
        if (assignments[target]) {
          const prev = assignments[target];
          prev.disabled = false;
          prev.classList.remove("disabled");
        }
        values[target] = value;
        assignments[target] = btn;
        btn.disabled = true;
        btn.classList.add("disabled");
        refreshSlots();
        const next = values.findIndex((v) => !v);
        setActive(next);
      };

      slots.forEach((slot, idx) => {
        slot.addEventListener("click", () => {
          if (values[idx]) {
            clearSlot(idx);
          } else {
            setActive(idx);
          }
        });
      });

      tokens.forEach((btn) => {
        btn.addEventListener("click", () => assignValue(btn));
      });
    });
  }

  function setupFillQuestions() {
    document.querySelectorAll("[data-fill-question]").forEach((container) => {
      const inputs = Array.from(container.querySelectorAll("[data-fill-input]"));
      if (!inputs.length) return;
      const hidden = container.querySelector("[data-fill-answer]");
      const update = () => {
        const parts = inputs.map((el) => el.value || "");
        if (hidden) hidden.value = parts.join("||");
      };
      inputs.forEach((input) => {
        input.addEventListener("input", update);
        input.addEventListener("change", update);
      });
    });
  }

  function setupMarkdownAnswers() {
    const areas = Array.from(document.querySelectorAll("textarea[data-markdown-answer]"));
    if (!areas.length) return;
    const render = (area) => {
      const qid = area.dataset.markdownAnswer;
      const preview = document.querySelector(`[data-markdown-preview="${qid}"]`);
      if (!preview) return;
      preview.innerHTML = renderMarkdownText(area.value || "");
    };
    areas.forEach((area) => {
      render(area);
      area.addEventListener("input", () => render(area));
      area.addEventListener("change", () => render(area));
    });
  }

  function setupMarkdownStatic() {
    const blocks = document.querySelectorAll("[data-markdown-prompt], [data-markdown-statement], [data-markdown-instructions]");
    if (!blocks.length) return;
    blocks.forEach((block) => {
      const content = (block.textContent || "").trim();
      block.innerHTML = renderMarkdownText(content);
      block.style.whiteSpace = "normal";
      block.style.fontFamily = "system-ui, -apple-system, 'Segoe UI', sans-serif";
    });
  }

  function setupCodeReset() {
    const buttons = Array.from(document.querySelectorAll("[data-code-reset]"));
    if (!buttons.length) return;
    buttons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.dataset.target;
        const area = document.querySelector(`textarea[data-code-input="${target}"]`);
        if (!area) return;
        const initial = area.dataset.codeInitial !== undefined ? area.dataset.codeInitial : (btn.dataset.initial || "");
        area.value = initial;
        if (area._monacoEditor) {
          area._monacoEditor.setValue(initial);
        } else {
          const ev = new Event("input", { bubbles: true });
          area.dispatchEvent(ev);
        }
      });
    });
  }

  setupExamBuilder();
  setupCodeEditors();
  setupCodeReset();
  setupMarkdownStatic();
  setupMarkdownAnswers();
  setupExamRunner();
  setupTokenQuestions();
  setupFillQuestions();
})();
