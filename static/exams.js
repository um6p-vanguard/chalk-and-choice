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
    const lines = (text || "").replace(/\r\n/g, "\n").split("\n");
    const parts = [];
    let inList = false;
    let inCode = false;
    let inMath = false;
    let codeLines = [];
    let codeLang = "";
    let mathLines = [];
    const flushCode = () => {
      const langAttr = codeLang ? ` data-lang="${escapeHtml(codeLang)}"` : "";
      const codeHtml = escapeHtml(codeLines.join("\n"));
      parts.push(`<pre class="md-code"><code${langAttr}>${codeHtml}</code></pre>`);
      codeLines = [];
      codeLang = "";
    };
    const flushMath = () => {
      const mathHtml = escapeHtml(mathLines.join("\n"));
      parts.push(`<div class="md-math">$$\n${mathHtml}\n$$</div>`);
      mathLines = [];
    };
    lines.forEach((line) => {
      const fence = line.trim().match(/^```(.*)$/);
      if (fence) {
        if (inCode) {
          flushCode();
          inCode = false;
        } else {
          if (inList) {
            parts.push("</ul>");
            inList = false;
          }
          inCode = true;
          codeLang = (fence[1] || "").trim();
        }
        return;
      }
      if (inCode) {
        codeLines.push(line);
        return;
      }
      const trimmed = line.trim();
      if (!inMath) {
        if (trimmed.startsWith("$$") && trimmed.endsWith("$$") && trimmed.length > 4) {
          if (inList) {
            parts.push("</ul>");
            inList = false;
          }
          const content = trimmed.slice(2, -2).trim();
          const mathHtml = escapeHtml(content);
          parts.push(`<div class="md-math">$$\n${mathHtml}\n$$</div>`);
          return;
        }
        if (trimmed === "$$") {
          if (inList) {
            parts.push("</ul>");
            inList = false;
          }
          inMath = true;
          mathLines = [];
          return;
        }
      } else {
        if (trimmed === "$$") {
          flushMath();
          inMath = false;
          return;
        }
        mathLines.push(line);
        return;
      }
      const heading = line.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        if (inList) {
          parts.push("</ul>");
          inList = false;
        }
        const level = heading[1].length;
        parts.push(`<h${level} class="md-heading">${inlineMarkdown(heading[2].trim())}</h${level}>`);
        return;
      }
      const listMatch = line.match(/^\s*-\s+(.*)/);
      if (listMatch) {
        if (!inList) {
          parts.push("<ul class=\"md-list\">");
          inList = true;
        }
        parts.push(`<li>${inlineMarkdown(listMatch[1])}</li>`);
        return;
      }
      if (inList) {
        parts.push("</ul>");
        inList = false;
      }
      if (!line.trim()) {
        parts.push("<br>");
      } else {
        parts.push(`<p class="md-p">${inlineMarkdown(line)}</p>`);
      }
    });
    if (inCode) {
      flushCode();
    }
    if (inMath) {
      flushMath();
    }
    if (inList) parts.push("</ul>");
    return parts.join("");
  };

  const renderMarkdownInline = (text) => inlineMarkdown(text || "").replace(/\n/g, "<br>");

  const typesetMath = (root) => {
    const mj = window.MathJax;
    if (!mj || typeof mj.typesetPromise !== "function") return;
    const nodes = root ? [root] : [document.body];
    if (typeof mj.typesetClear === "function") {
      mj.typesetClear(nodes);
    }
    mj.typesetPromise(nodes).catch(() => {});
  };

  function disableClipboardOnInput(element) {
    if (!element || element.dataset.clipboardGuard === "1") return;
    element.dataset.clipboardGuard = "1";
    const blockEvent = (evt) => {
      evt.preventDefault();
      evt.stopPropagation();
      evt.returnValue = false;
      if (typeof evt.stopImmediatePropagation === "function") {
        evt.stopImmediatePropagation();
      }
      return false;
    };
    const keyHandler = (evt) => {
      const ctrlOrCmd = evt.ctrlKey || evt.metaKey;
      const key = (evt.key || "").toLowerCase();
      const ctrlAction = ctrlOrCmd && ["c", "x", "v"].includes(key);
      const shiftInsert = evt.shiftKey && key === "insert";
      const ctrlInsert = ctrlOrCmd && key === "insert";
      const shiftDelete = evt.shiftKey && key === "delete";
      if (ctrlAction || shiftInsert || ctrlInsert || shiftDelete) {
        blockEvent(evt);
      }
    };
    element.addEventListener("keydown", keyHandler);
    ["copy", "cut", "paste", "drop", "contextmenu"].forEach((type) => {
      element.addEventListener(type, blockEvent);
    });
  }

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
    const taskKindField = root.querySelector("[data-task-kind-value]");
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
        const selector = mode === "script" ? '[data-sample-list="script"]' : '[data-sample-list="callable"]';
        const container = card.querySelector(selector);
        if (container) {
          const row = mode === "script" ? buildScriptSampleRow() : buildCallableSampleRow({}, mode);
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
      if (taskKindField && (taskKindField.value || "assessment") === "tutorial") {
        hidden.value = "[]";
        return;
      }
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
    } else if (!taskKindField || (taskKindField.value || "assessment") !== "tutorial") {
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
        <button type="button" class="btn" data-mode-choice="class">Class (init + method call)</button>
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

      const classSignatureWrap = document.createElement("div");
      classSignatureWrap.dataset.codeMode = "class-signature";
      classSignatureWrap.style.marginTop = "10px";
      const classSignatureLabel = document.createElement("label");
      classSignatureLabel.textContent = "Class signature";
      classSignatureWrap.appendChild(classSignatureLabel);
      const classSignatureInput = document.createElement("input");
      classSignatureInput.type = "text";
      classSignatureInput.dataset.field = "class-signature";
      classSignatureInput.placeholder = "class Counter:";
      classSignatureInput.value = data.class_signature || "";
      classSignatureWrap.appendChild(classSignatureInput);
      card.appendChild(classSignatureWrap);

      const initWrap = document.createElement("div");
      initWrap.dataset.codeMode = "class-init";
      initWrap.style.marginTop = "10px";
      const initLabel = document.createElement("label");
      initLabel.textContent = "__init__ call";
      initWrap.appendChild(initLabel);
      const initInput = document.createElement("input");
      initInput.type = "text";
      initInput.dataset.field = "class-init";
      initInput.placeholder = "Counter(0)";
      initInput.value = data.class_init || "";
      initWrap.appendChild(initInput);
      const initHelp = document.createElement("p");
      initHelp.className = "muted";
      initHelp.style.marginTop = "6px";
      initHelp.textContent = "A fresh object is created before each test and exposed as obj.";
      initWrap.appendChild(initHelp);
      card.appendChild(initWrap);

      const sampleHeader = document.createElement("div");
      sampleHeader.className = "row";
      sampleHeader.style.justifyContent = "space-between";
      sampleHeader.style.alignItems = "center";
      sampleHeader.style.marginTop = "10px";
      sampleHeader.innerHTML = `<strong>Public samples</strong>
        <button type="button" class="btn" data-action="add-sample">Add sample</button>`;
      card.appendChild(sampleHeader);

      const sampleHelper = document.createElement("p");
      sampleHelper.className = "muted";
      sampleHelper.style.marginTop = "-4px";
      sampleHelper.textContent = "Provide public sample cases for the student-facing runner. Use hidden tests below for final judging.";
      card.appendChild(sampleHelper);

      const scriptSampleList = document.createElement("div");
      scriptSampleList.dataset.sampleList = "script";
      scriptSampleList.style.display = "flex";
      scriptSampleList.style.flexDirection = "column";
      scriptSampleList.style.gap = "10px";
      card.appendChild(scriptSampleList);

      const callableSampleList = document.createElement("div");
      callableSampleList.dataset.sampleList = "callable";
      callableSampleList.style.display = "flex";
      callableSampleList.style.flexDirection = "column";
      callableSampleList.style.gap = "10px";
      card.appendChild(callableSampleList);

      const samples = Array.isArray(data.samples) && data.samples.length ? data.samples : [{}];
      samples.forEach((sample) => {
        if (sample.call) {
          callableSampleList.appendChild(buildCallableSampleRow(sample, data.mode || "function"));
        } else {
          scriptSampleList.appendChild(buildScriptSampleRow(sample));
        }
      });
      if (!scriptSampleList.children.length) {
        scriptSampleList.appendChild(buildScriptSampleRow());
      }
      if (!callableSampleList.children.length) {
        callableSampleList.appendChild(buildCallableSampleRow({}, data.mode || "function"));
      }

      const hiddenTestsLabel = document.createElement("label");
      hiddenTestsLabel.textContent = "Hidden tests JSON (optional)";
      card.appendChild(hiddenTestsLabel);

      const hiddenTestsField = document.createElement("textarea");
      hiddenTestsField.rows = 10;
      hiddenTestsField.dataset.field = "hidden-tests-json";
      hiddenTestsField.placeholder = '[\n  {\n    "name": "large case",\n    "stdin_file": "cases/large.in",\n    "expected_file": "cases/large.out",\n    "timeout_ms": 1200\n  }\n]';
      if (typeof data.hidden_tests_json === "string" && data.hidden_tests_json.trim()) {
        hiddenTestsField.value = data.hidden_tests_json.trim();
      } else if (Array.isArray(data.hidden_tests) && data.hidden_tests.length) {
        hiddenTestsField.value = JSON.stringify(data.hidden_tests, null, 2);
      } else {
        hiddenTestsField.value = "";
      }
      card.appendChild(hiddenTestsField);

      const hiddenTestsHelp = document.createElement("p");
      hiddenTestsHelp.className = "muted";
      hiddenTestsHelp.style.marginTop = "6px";
      hiddenTestsHelp.textContent = "Private tests run only on final submit. Use stdin_file, expected_file, or mounted files when the task has a judge bundle ZIP.";
      card.appendChild(hiddenTestsHelp);

      const updateModeUI = () => {
        const mode = modeField.value || "script";
        scriptSampleList.style.display = mode === "script" ? "flex" : "none";
        callableSampleList.style.display = mode === "script" ? "none" : "flex";
        signatureWrap.style.display = mode === "function" ? "block" : "none";
        classSignatureWrap.style.display = mode === "class" ? "block" : "none";
        initWrap.style.display = mode === "class" ? "block" : "none";
        sampleHelper.textContent = mode === "script"
          ? "Provide public input/output sample pairs for script mode and choose a text comparison rule."
          : mode === "class"
            ? "Set the __init__ call once, then provide public method-call samples that run against obj and choose how results are compared."
            : "Provide public function-call samples, expected returns, and the comparison rule for each sample.";
        callableSampleList.querySelectorAll("[data-sample-row]").forEach((row) => {
          setCallableSampleRowMode(row, mode);
        });
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
    } else if (type === "plot") {
      const info = document.createElement("p");
      info.className = "muted";
      info.textContent = "Students write Python that generates a matplotlib plot. The latest PNG preview is uploaded only when they submit.";
      card.appendChild(info);

      const statementLabel = document.createElement("label");
      statementLabel.textContent = "Plot instructions";
      card.appendChild(statementLabel);
      const statement = document.createElement("textarea");
      statement.rows = 4;
      statement.dataset.field = "statement";
      statement.placeholder = "Describe the required chart, labels, annotations, and style constraints.";
      statement.value = data.statement || "";
      card.appendChild(statement);

      const starterLabel = document.createElement("label");
      starterLabel.textContent = "Starter code";
      card.appendChild(starterLabel);
      const starter = document.createElement("textarea");
      starter.rows = 8;
      starter.dataset.field = "starter";
      starter.placeholder = "import matplotlib.pyplot as plt\n";
      starter.value = data.starter || "";
      card.appendChild(starter);
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
    } else if (type === "file") {
      const info = document.createElement("p");
      info.className = "muted";
      info.textContent = "Students upload a .zip file (max 5 MB).";
      card.appendChild(info);
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

  const DEFAULT_SCRIPT_COMPARE_MODE = "rstrip";
  const DEFAULT_CALLABLE_COMPARE_MODE = "exact";
  const DEFAULT_NUMERIC_TOLERANCE = "1e-6";

  const SCRIPT_SAMPLE_COMPARE_OPTIONS = [
    { value: "rstrip", label: "Ignore trailing whitespace" },
    { value: "exact", label: "Exact text" },
    { value: "normalize_whitespace", label: "Normalize whitespace" },
    { value: "contains", label: "Contains text" },
  ];

  const CALLABLE_SAMPLE_COMPARE_OPTIONS = [
    { value: "exact", label: "Exact result" },
    { value: "numeric_tolerance", label: "Numeric tolerance" },
    { value: "contains", label: "Result text contains" },
  ];

  function buildSampleCompareSelect(options, value, fallbackValue) {
    const select = document.createElement("select");
    select.dataset.field = "sample-compare-mode";
    const selected = value || fallbackValue;
    options.forEach((option) => {
      const opt = document.createElement("option");
      opt.value = option.value;
      opt.textContent = option.label;
      if (option.value === selected) opt.selected = true;
      select.appendChild(opt);
    });
    return select;
  }

  function describeSampleComparison(sample) {
    const mode = (sample && sample.mode) || "script";
    const compareMode = (sample && sample.compare_mode) || (mode === "script" ? DEFAULT_SCRIPT_COMPARE_MODE : DEFAULT_CALLABLE_COMPARE_MODE);
    if (mode === "script") {
      if (compareMode === "exact") return "Comparison: exact text";
      if (compareMode === "normalize_whitespace") return "Comparison: normalized whitespace";
      if (compareMode === "contains") return "Comparison: contains text";
      return "Comparison: ignore trailing whitespace";
    }
    if (compareMode === "numeric_tolerance") {
      const tolerance = sample && sample.tolerance !== undefined && sample.tolerance !== null && String(sample.tolerance).trim()
        ? sample.tolerance
        : DEFAULT_NUMERIC_TOLERANCE;
      return `Comparison: numeric tolerance (${tolerance})`;
    }
    if (compareMode === "contains") return "Comparison: result text contains";
    return "Comparison: exact result";
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

    const compareLabel = document.createElement("label");
    compareLabel.textContent = "Comparison";
    wrapper.appendChild(compareLabel);

    const compareSelect = buildSampleCompareSelect(
      SCRIPT_SAMPLE_COMPARE_OPTIONS,
      sample.compare_mode || sample.compare || "",
      DEFAULT_SCRIPT_COMPARE_MODE,
    );
    wrapper.appendChild(compareSelect);

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

  function callableSampleMeta(mode) {
    if (mode === "class") {
      return {
        callLabel: "Method call / expression",
        callPlaceholder: "obj.increment()",
        expectedLabel: "Expected result",
      };
    }
    return {
      callLabel: "Function call",
      callPlaceholder: "square(5)",
      expectedLabel: "Expected return",
    };
  }

  function setCallableSampleRowMode(wrapper, mode) {
    if (!wrapper) return;
    const meta = callableSampleMeta(mode);
    wrapper.dataset.callableMode = mode || "function";
    const callLabel = wrapper.querySelector('[data-role="sample-call-label"]');
    const callInput = wrapper.querySelector('[data-field="sample-call"]');
    const expectedLabel = wrapper.querySelector('[data-role="sample-expected-label"]');
    if (callLabel) callLabel.textContent = meta.callLabel;
    if (callInput) callInput.placeholder = meta.callPlaceholder;
    if (expectedLabel) expectedLabel.textContent = meta.expectedLabel;
  }

  function updateCallableSampleCompareUI(wrapper) {
    if (!wrapper) return;
    const compareSelect = wrapper.querySelector('[data-field="sample-compare-mode"]');
    const toleranceWrap = wrapper.querySelector('[data-role="sample-tolerance-wrap"]');
    const toleranceInput = wrapper.querySelector('[data-field="sample-tolerance"]');
    const compareMode = compareSelect ? (compareSelect.value || DEFAULT_CALLABLE_COMPARE_MODE) : DEFAULT_CALLABLE_COMPARE_MODE;
    if (toleranceWrap) {
      toleranceWrap.style.display = compareMode === "numeric_tolerance" ? "block" : "none";
    }
    if (toleranceInput && compareMode === "numeric_tolerance" && !String(toleranceInput.value || "").trim()) {
      toleranceInput.value = DEFAULT_NUMERIC_TOLERANCE;
    }
  }

  function buildCallableSampleRow(sample = {}, mode = "function") {
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
    callLabel.dataset.role = "sample-call-label";
    wrapper.appendChild(callLabel);

    const callInput = document.createElement("input");
    callInput.type = "text";
    callInput.dataset.field = "sample-call";
    callInput.value = sample.call || sample.input || "";
    wrapper.appendChild(callInput);

    const expectedLabel = document.createElement("label");
    expectedLabel.dataset.role = "sample-expected-label";
    wrapper.appendChild(expectedLabel);

    const expectedInput = document.createElement("textarea");
    expectedInput.rows = 3;
    expectedInput.dataset.field = "sample-expected";
    expectedInput.value = sample.expected || sample.output || "";
    wrapper.appendChild(expectedInput);

    const compareLabel = document.createElement("label");
    compareLabel.textContent = "Comparison";
    wrapper.appendChild(compareLabel);

    const compareSelect = buildSampleCompareSelect(
      CALLABLE_SAMPLE_COMPARE_OPTIONS,
      sample.compare_mode || sample.compare || "",
      DEFAULT_CALLABLE_COMPARE_MODE,
    );
    wrapper.appendChild(compareSelect);

    const toleranceWrap = document.createElement("div");
    toleranceWrap.dataset.role = "sample-tolerance-wrap";
    toleranceWrap.style.marginTop = "8px";
    const toleranceLabel = document.createElement("label");
    toleranceLabel.textContent = "Tolerance";
    toleranceWrap.appendChild(toleranceLabel);
    const toleranceInput = document.createElement("input");
    toleranceInput.type = "text";
    toleranceInput.dataset.field = "sample-tolerance";
    toleranceInput.placeholder = DEFAULT_NUMERIC_TOLERANCE;
    toleranceInput.value = sample.tolerance !== undefined && sample.tolerance !== null ? String(sample.tolerance) : "";
    toleranceWrap.appendChild(toleranceInput);
    const toleranceHelp = document.createElement("p");
    toleranceHelp.className = "muted";
    toleranceHelp.style.marginTop = "6px";
    toleranceHelp.textContent = "Absolute tolerance for numbers or arrays, for example 1e-6.";
    toleranceWrap.appendChild(toleranceHelp);
    wrapper.appendChild(toleranceWrap);

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

    setCallableSampleRowMode(wrapper, mode);
    compareSelect.addEventListener("change", () => {
      updateCallableSampleCompareUI(wrapper);
    });
    updateCallableSampleCompareUI(wrapper);
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
        const hiddenTestsJson = getFieldValue(card, "hidden-tests-json");
        if (String(hiddenTestsJson || "").trim()) {
          payload.hidden_tests_json = hiddenTestsJson;
        }
        if (mode === "function") {
          payload.function_signature = getFieldValue(card, "function-signature");
          const rows = card.querySelectorAll('[data-sample-list="callable"] [data-sample-row]');
          payload.samples = Array.from(rows).map((row) => {
            const compareMode = getFieldValue(row, "sample-compare-mode") || DEFAULT_CALLABLE_COMPARE_MODE;
            const sample = {
              name: getFieldValue(row, "sample-name"),
              call: getFieldValue(row, "sample-call"),
              expected: getFieldValue(row, "sample-expected"),
              compare_mode: compareMode,
              hidden: !!row.querySelector('[data-field="sample-hidden"]')?.checked,
            };
            if (compareMode === "numeric_tolerance") {
              sample.tolerance = getFieldValue(row, "sample-tolerance");
            }
            return sample;
          });
        } else if (mode === "class") {
          const classInit = getFieldValue(card, "class-init");
          payload.class_signature = getFieldValue(card, "class-signature");
          payload.class_init = classInit;
          const rows = card.querySelectorAll('[data-sample-list="callable"] [data-sample-row]');
          payload.samples = Array.from(rows).map((row) => {
            const compareMode = getFieldValue(row, "sample-compare-mode") || DEFAULT_CALLABLE_COMPARE_MODE;
            const sample = {
              name: getFieldValue(row, "sample-name"),
              call: getFieldValue(row, "sample-call"),
              expected: getFieldValue(row, "sample-expected"),
              init_call: classInit,
              compare_mode: compareMode,
              hidden: !!row.querySelector('[data-field="sample-hidden"]')?.checked,
            };
            if (compareMode === "numeric_tolerance") {
              sample.tolerance = getFieldValue(row, "sample-tolerance");
            }
            return sample;
          });
        } else {
          const rows = card.querySelectorAll('[data-sample-list="script"] [data-sample-row]');
          payload.samples = Array.from(rows).map((row) => ({
            name: getFieldValue(row, "sample-name"),
            input: getFieldValue(row, "sample-input"),
            output: getFieldValue(row, "sample-output"),
            compare_mode: getFieldValue(row, "sample-compare-mode") || DEFAULT_SCRIPT_COMPARE_MODE,
            hidden: !!row.querySelector('[data-field="sample-hidden"]')?.checked,
          }));
        }
      } else if (type === "plot") {
        payload.statement = getFieldValue(card, "statement");
        payload.starter = getFieldValue(card, "starter");
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
    const plotButtons = root.querySelectorAll("[data-run-plot]");
    const form = root.querySelector("[data-exam-form]");
    const artifactNamespace = root.dataset.artifactNamespace || "";
    if (!buttons.length && !customButtons.length && !plotButtons.length && !form) return;
    let pyodidePromise = null;
    let packagesPromise = null;
    let plotDbPromise = null;
    const plotRuntimeState = new Map();
    let hiddenMatplotlibTarget = null;

    const ensurePyodide = async () => {
      if (!window.loadPyodide) {
        throw new Error("Pyodide script not loaded");
      }
      if (!pyodidePromise) {
        pyodidePromise = loadPyodide({ indexURL: "https://cdn.jsdelivr.net/pyodide/v0.24.1/full/" });
      }
      return pyodidePromise;
    };
    const ensurePackages = async () => {
      const pyodide = await ensurePyodide();
      if (!packagesPromise) {
        packagesPromise = pyodide.loadPackage(["numpy", "matplotlib"]);
      }
      await packagesPromise;
      return pyodide;
    };
    const ensureHiddenMatplotlibTarget = () => {
      if (!document.body) return null;
      if (hiddenMatplotlibTarget && hiddenMatplotlibTarget.isConnected) {
        return hiddenMatplotlibTarget;
      }
      hiddenMatplotlibTarget = document.createElement("div");
      hiddenMatplotlibTarget.setAttribute("data-hidden-matplotlib-target", "true");
      hiddenMatplotlibTarget.setAttribute("aria-hidden", "true");
      Object.assign(hiddenMatplotlibTarget.style, {
        position: "fixed",
        left: "-10000px",
        top: "0",
        width: "1px",
        height: "1px",
        overflow: "hidden",
        opacity: "0",
        pointerEvents: "none",
      });
      document.body.appendChild(hiddenMatplotlibTarget);
      return hiddenMatplotlibTarget;
    };
    const clearHiddenMatplotlibTarget = () => {
      if (hiddenMatplotlibTarget) {
        hiddenMatplotlibTarget.replaceChildren();
      }
    };
    const listVisibleMatplotlibRoots = () => Array.from(document.querySelectorAll('div[id^="matplotlib_"]'))
      .filter((node) => node.querySelector('canvas[id^="matplotlib_"]'))
      .filter((node) => !node.closest("[data-hidden-matplotlib-target]"));

    const logUrl = root.dataset.runLogUrl;
    const csrf = root.dataset.csrf;
    const autoInput = form ? form.querySelector('input[name="nav_action_auto"]') : null;

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

    const openPlotDb = async () => {
      if (!("indexedDB" in window)) return null;
      if (!plotDbPromise) {
        plotDbPromise = new Promise((resolve, reject) => {
          const request = window.indexedDB.open("chalk_and_choice_plot_artifacts", 1);
          request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains("artifacts")) {
              const store = db.createObjectStore("artifacts", { keyPath: "id" });
              store.createIndex("namespace", "namespace", { unique: false });
            }
          };
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error || new Error("Unable to open plot cache"));
        }).catch((err) => {
          console.warn("Plot cache unavailable", err);
          return null;
        });
      }
      return plotDbPromise;
    };

    const plotKey = (namespace, questionId) => `${namespace}:${questionId}`;

    const loadPlotArtifact = async (namespace, questionId) => {
      const db = await openPlotDb();
      if (!db) return null;
      return new Promise((resolve) => {
        const tx = db.transaction("artifacts", "readonly");
        const req = tx.objectStore("artifacts").get(plotKey(namespace, questionId));
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      });
    };

    const savePlotArtifact = async (namespace, questionId, record) => {
      const db = await openPlotDb();
      if (!db) return;
      await new Promise((resolve) => {
        const tx = db.transaction("artifacts", "readwrite");
        tx.objectStore("artifacts").put({
          ...record,
          id: plotKey(namespace, questionId),
          namespace,
          questionId,
        });
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
      });
    };

    const deletePlotArtifact = async (namespace, questionId) => {
      const db = await openPlotDb();
      if (!db) return;
      await new Promise((resolve) => {
        const tx = db.transaction("artifacts", "readwrite");
        tx.objectStore("artifacts").delete(plotKey(namespace, questionId));
        tx.oncomplete = () => resolve();
        tx.onerror = () => resolve();
      });
    };

    const getNamespaceArtifacts = async (namespace) => {
      const db = await openPlotDb();
      if (!db) return [];
      return new Promise((resolve) => {
        const tx = db.transaction("artifacts", "readonly");
        const index = tx.objectStore("artifacts").index("namespace");
        const items = [];
        const req = index.openCursor(window.IDBKeyRange.only(namespace));
        req.onsuccess = () => {
          const cursor = req.result;
          if (!cursor) {
            resolve(items);
            return;
          }
          items.push(cursor.value);
          cursor.continue();
        };
        req.onerror = () => resolve(items);
      });
    };

    const clearNamespaceArtifacts = async (namespace) => {
      const items = await getNamespaceArtifacts(namespace);
      await Promise.all(items.map((item) => deletePlotArtifact(namespace, item.questionId)));
    };
    const clearInjectedPlotFields = () => {
      if (!form) return;
      form.querySelectorAll("[data-plot-upload-proxy]").forEach((node) => node.remove());
    };
    const injectPlotArtifactsIntoForm = (artifacts) => {
      if (!form || !Array.isArray(artifacts) || !artifacts.length) return false;
      clearInjectedPlotFields();
      let injected = false;
      artifacts.forEach((record) => {
        if (!record || !record.questionId || !record.blob) return;
        const fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.name = `plot_artifact_${record.questionId}`;
        fileInput.hidden = true;
        fileInput.setAttribute("data-plot-upload-proxy", "true");
        try {
          const transfer = new DataTransfer();
          transfer.items.add(
            new File([record.blob], `plot-${record.questionId}.png`, { type: "image/png" }),
          );
          fileInput.files = transfer.files;
        } catch (err) {
          return;
        }
        const metaInput = document.createElement("input");
        metaInput.type = "hidden";
        metaInput.name = `plot_meta_${record.questionId}`;
        metaInput.value = JSON.stringify({
          status: record.status || "passed",
          stdout: record.stdout || "",
          error: record.error || "",
          code_snapshot: record.codeSnapshot || "",
          plot_count: record.plotCount || 1,
        });
        metaInput.setAttribute("data-plot-upload-proxy", "true");
        form.appendChild(fileInput);
        form.appendChild(metaInput);
        injected = true;
      });
      return injected;
    };

    const revokePlotObjectUrl = (questionId) => {
      const state = plotRuntimeState.get(questionId);
      if (state && state.objectUrl) {
        URL.revokeObjectURL(state.objectUrl);
      }
    };

    const base64ToBlob = (base64Data, type = "image/png") => {
      const raw = window.atob(base64Data || "");
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i += 1) {
        bytes[i] = raw.charCodeAt(i);
      }
      return new Blob([bytes], { type });
    };
    const normalizeCodeText = (value) => {
      const normalized = String(value || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      const lines = normalized.split("\n").map((line) => line.replace(/[ \t]+$/g, ""));
      while (lines.length && lines[lines.length - 1] === "") {
        lines.pop();
      }
      return lines.join("\n");
    };

    const setPlotSummary = (questionId, text, color) => {
      const summaryEl = root.querySelector(`[data-plot-summary="${questionId}"]`);
      if (!summaryEl) return;
      summaryEl.textContent = text;
      summaryEl.style.color = color || "#94a3b8";
      summaryEl.style.borderColor = "#334155";
    };

    const renderPlotPreview = (questionId, record, currentCode = "") => {
      const preview = root.querySelector(`[data-plot-preview="${questionId}"]`);
      if (!preview) return;
      const normalizedCurrentCode = normalizeCodeText(currentCode);
      const isFresh = !!record
        && typeof record.codeSnapshot === "string"
        && record.codeSnapshot === normalizedCurrentCode;
      const imageUrl = record ? (record.url || null) : null;

      if (!record || (!record.blob && !imageUrl)) {
        revokePlotObjectUrl(questionId);
        plotRuntimeState.delete(questionId);
        preview.innerHTML = `<p class="muted" style="margin:0;">Run the code to generate a preview. The latest PNG will be uploaded only when you submit.</p>`;
        setPlotSummary(questionId, "Not run", "#94a3b8");
        return;
      }

      revokePlotObjectUrl(questionId);
      const nextState = { ...record };
      if (record.blob) {
        nextState.objectUrl = URL.createObjectURL(record.blob);
      }
      plotRuntimeState.set(questionId, nextState);
      const details = [];
      if (record.plotCount && record.plotCount > 1) {
        details.push(`${record.plotCount} figures generated`);
      }
      if (record.updatedAt) {
        details.push(`Last run: ${record.updatedAt}`);
      }
      preview.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:8px;">
          <img src="${nextState.objectUrl || nextState.url || ""}" alt="Latest plot preview" style="display:block; width:100%; max-height:520px; object-fit:contain; border:1px solid #1f2937; border-radius:10px; background:#0f172a;">
          <div class="muted" style="font-size:0.85rem;">${details.join(" • ") || "Latest plot preview"}</div>
          ${record.stdout ? `<div><div class="muted">Stdout</div><pre style="white-space:pre-wrap; background:#0f172a; padding:8px; border-radius:8px; border:1px solid #1f2937;">${escapeHtml(record.stdout)}</pre></div>` : ""}
          ${record.error ? `<div><div class="muted">Runner message</div><pre style="white-space:pre-wrap; background:#1f2937; padding:8px; border-radius:8px; border:1px solid #334155;">${escapeHtml(record.error)}</pre></div>` : ""}
          ${isFresh ? `<div class="muted" style="font-size:0.85rem;">This preview matches the current code.</div>` : `<div style="font-size:0.85rem; color:#fbbf24;">Code changed since the last successful run. Run the plot again before submitting.</div>`}
        </div>
      `;
      setPlotSummary(questionId, isFresh ? "Ready" : "Stale", isFresh ? "#4ade80" : "#fbbf24");
    };

    const syncPlotPreviewFromCache = async (questionId) => {
      const area = root.querySelector(`[data-code-input="${questionId}"]`);
      const preview = root.querySelector(`[data-plot-preview="${questionId}"]`);
      if (!artifactNamespace) {
        if (preview && preview.dataset.existingUrl) {
          renderPlotPreview(questionId, {
            url: preview.dataset.existingUrl,
            codeSnapshot: area ? normalizeCodeText(area.value || "") : "",
            stdout: preview.dataset.existingStdout || "",
            error: preview.dataset.existingError || "",
            updatedAt: preview.dataset.existingUpdatedAt || "",
            plotCount: parseInt(preview.dataset.existingPlotCount || "1", 10) || 1,
          }, area ? area.value : "");
        }
        return;
      }
      const cached = await loadPlotArtifact(artifactNamespace, questionId);
      if (!cached) {
        if (preview && preview.dataset.existingUrl) {
          renderPlotPreview(questionId, {
            url: preview.dataset.existingUrl,
            codeSnapshot: area ? normalizeCodeText(area.value || "") : "",
            stdout: preview.dataset.existingStdout || "",
            error: preview.dataset.existingError || "",
            updatedAt: preview.dataset.existingUpdatedAt || "",
            plotCount: parseInt(preview.dataset.existingPlotCount || "1", 10) || 1,
          }, area ? area.value : "");
          return;
        }
        renderPlotPreview(questionId, null, area ? area.value : "");
        return;
      }
      plotRuntimeState.set(questionId, cached);
      renderPlotPreview(questionId, cached, area ? area.value : "");
    };

    const attachPlotStaleTracker = (questionId) => {
      const area = root.querySelector(`[data-code-input="${questionId}"]`);
      if (!area || area.dataset.plotWatchAttached === "1") return;
      area.dataset.plotWatchAttached = "1";
      const refresh = () => {
        const state = plotRuntimeState.get(questionId);
        if (!state) return;
        renderPlotPreview(questionId, state, area.value || "");
      };
      area.addEventListener("input", refresh);
      area.addEventListener("change", refresh);
      window.setTimeout(refresh, 250);
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

        const labelInput = sample.mode === "class" ? "Method call" : sample.mode === "function" ? "Call" : "Input";
        const outputLabel = sample.mode === "script" ? "Your output" : "Your result";
        const expectedLabel = sample.mode === "script" ? "Expected output" : "Expected result";
        if (sample.mode === "class" && sample.init_call) {
          const initBlock = document.createElement("div");
          initBlock.innerHTML = `
            <div class="muted">Init</div>
            <pre style="white-space:pre-wrap; background:#0b1220; padding:8px; border-radius:8px; font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">${escapeHtml(sample.init_call || "")}</pre>
          `;
          details.appendChild(initBlock);
        }
        const inputBlock = document.createElement("div");
        inputBlock.style.marginTop = sample.mode === "class" && sample.init_call ? "8px" : "0";
        inputBlock.innerHTML = `
          <div class="muted">${labelInput}</div>
          <pre style="white-space:pre-wrap; background:#0b1220; padding:8px; border-radius:8px; font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">${escapeHtml(sample.input || "")}</pre>
        `;

        const outputBlock = document.createElement("div");
        outputBlock.style.marginTop = "8px";
        outputBlock.innerHTML = `
          <div class="muted">${outputLabel}</div>
          <pre style="white-space:pre-wrap; background:#0b1220; padding:8px; border-radius:8px; font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">${escapeHtml(sample.output || "")}</pre>
        `;

        const expectedBlock = document.createElement("div");
        expectedBlock.style.marginTop = "8px";
        expectedBlock.innerHTML = `
          <div class="muted">${expectedLabel}</div>
          <pre style="white-space:pre-wrap; background:#0b1220; padding:8px; border-radius:8px; font-family:SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">${escapeHtml(sample.expected || "")}</pre>
        `;

        details.appendChild(inputBlock);
        details.appendChild(outputBlock);
        details.appendChild(expectedBlock);

        const compareInfo = document.createElement("div");
        compareInfo.className = "muted";
        compareInfo.style.marginTop = "8px";
        compareInfo.textContent = describeSampleComparison(sample);
        details.appendChild(compareInfo);

        if (sample.expected && (sample.output || sample.output === "")) {
          const diffWrap = buildDiff(sample.expected, sample.output);
          const diffLabel = document.createElement("div");
          diffLabel.className = "muted";
          diffLabel.style.marginTop = "8px";
          diffLabel.textContent = sample.mode === "script" ? "Diff (expected vs your output)" : "Diff (expected vs your result)";
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
        if (Array.isArray(sample.plot_images) && sample.plot_images.length) {
          const plotWrap = document.createElement("div");
          plotWrap.style.marginTop = "10px";
          sample.plot_images.forEach((imgData, idx) => {
            if (!imgData) return;
            const label = document.createElement("div");
            label.className = "muted";
            label.style.marginTop = idx === 0 ? "0" : "8px";
            label.textContent = `Plot ${idx + 1}`;
            const img = document.createElement("img");
            img.src = `data:image/png;base64,${imgData}`;
            img.alt = `Plot ${idx + 1}`;
            img.style.display = "block";
            img.style.maxWidth = "100%";
            img.style.border = "1px solid #1f2937";
            img.style.borderRadius = "8px";
            img.style.marginTop = "6px";
            plotWrap.appendChild(label);
            plotWrap.appendChild(img);
          });
          details.appendChild(plotWrap);
        }

        card.appendChild(toggle);
        card.appendChild(details);
        container.appendChild(card);
      });
    };

    const executeSamples = async (triggerBtn, samples, modeOverride, codeOverride) => {
      const pyodide = await ensurePackages();
      const codeInput = root.querySelector(`[data-code-input="${triggerBtn.dataset.question}"]`);
      const codeValue = codeOverride !== undefined ? codeOverride : (codeInput ? codeInput.value : "");
      const mode = modeOverride || triggerBtn.getAttribute("data-mode") || "script";
      const classInit = triggerBtn.getAttribute("data-class-init") || "";
      const runnerSamples = mode === "class"
        ? (Array.isArray(samples) ? samples : []).map((sample) => ({
          ...sample,
          init_call: sample && sample.init_call ? sample.init_call : classInit,
        }))
        : samples;
      const hiddenTarget = ensureHiddenMatplotlibTarget();
      const hadPreviousTarget = Object.prototype.hasOwnProperty.call(document, "pyodideMplTarget");
      const previousTarget = hadPreviousTarget ? document.pyodideMplTarget : undefined;
      const existingVisibleRoots = new Set(listVisibleMatplotlibRoots());
      if (hiddenTarget) {
        clearHiddenMatplotlibTarget();
        document.pyodideMplTarget = hiddenTarget;
      }
      pyodide.globals.set("runner_code", codeValue);
      pyodide.globals.set("runner_samples", runnerSamples);
      pyodide.globals.set("runner_mode", mode);
      try {
        const output = await pyodide.runPythonAsync(`
import io, sys, traceback, json, builtins, ast, base64

plt = None
np = None
try:
    import numpy as np  # preload to keep user imports fast
except Exception:
    np = None
try:
    import matplotlib
    try:
        matplotlib.use("module://matplotlib_pyodide.wasm_backend")
    except Exception:
        pass
    import matplotlib.pyplot as plt
except Exception:
    plt = None

def _collect_plots():
    if plt is None:
        return []
    images = []
    max_width = 10.0
    max_height = 7.5
    export_dpi = 120
    try:
        figs = list(plt.get_fignums())
        for num in figs:
            fig = plt.figure(num)
            buf = io.BytesIO()
            original_size = None
            try:
                width, height = fig.get_size_inches()
                if width > 0 and height > 0:
                    scale = min(max_width / width, max_height / height, 1.0)
                    if scale < 1.0:
                        original_size = (width, height)
                        fig.set_size_inches(width * scale, height * scale, forward=False)
            except Exception:
                original_size = None
            fig.savefig(buf, format="png", bbox_inches="tight", pad_inches=0.1, dpi=export_dpi)
            if original_size:
                fig.set_size_inches(*original_size, forward=False)
            images.append(base64.b64encode(buf.getvalue()).decode("ascii"))
        plt.close("all")
    except Exception:
        try:
            plt.close("all")
        except Exception:
            pass
        return []
    return images

code = str(runner_code)
samples = runner_samples.to_py()
mode = str(runner_mode)

# ---- Hard limits (tune as you like) ----
MAX_SETUP_OPS = 500_000    # for exec(code) in function mode
MAX_RUN_OPS   = 2_000_000  # for each sample run

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

def _values_match(actual, expected):
    if np is not None:
        try:
            if isinstance(actual, np.ndarray) or isinstance(expected, np.ndarray):
                try:
                    return bool(np.array_equal(np.asarray(actual), np.asarray(expected), equal_nan=True))
                except TypeError:
                    return bool(np.array_equal(np.asarray(actual), np.asarray(expected)))
                except Exception:
                    return False
        except Exception:
            pass
    try:
        comparison = actual == expected
    except Exception:
        return False
    if np is not None:
        try:
            if isinstance(comparison, np.ndarray):
                return bool(comparison.all())
        except Exception:
            pass
    try:
        return bool(comparison)
    except Exception:
        return False

def _normalize_compare_text(value):
    return " ".join(str(value or "").split())

def _text_matches(actual_text, expected_text, compare_mode):
    actual = str(actual_text or "")
    expected = str(expected_text or "")
    if compare_mode == "exact":
        return actual == expected
    if compare_mode == "normalize_whitespace":
        return _normalize_compare_text(actual) == _normalize_compare_text(expected)
    if compare_mode == "contains":
        return expected in actual
    return actual.rstrip() == expected.rstrip()

def _numeric_values_close(actual, expected, tolerance):
    if isinstance(actual, (list, tuple)) and isinstance(expected, (list, tuple)):
        if len(actual) != len(expected):
            return False
        return all(_numeric_values_close(a, b, tolerance) for a, b in zip(actual, expected))
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False
    if isinstance(actual, (str, bytes)) or isinstance(expected, (str, bytes)):
        return False
    try:
        left = float(actual)
        right = float(expected)
    except Exception:
        return False
    if left != left and right != right:
        return True
    return abs(left - right) <= tolerance

def _values_close(actual, expected, tolerance):
    try:
        tolerance = max(float(tolerance), 0.0)
    except Exception:
        tolerance = 1e-6
    if np is not None:
        try:
            return bool(np.allclose(np.asarray(actual), np.asarray(expected), atol=tolerance, rtol=0.0, equal_nan=True))
        except Exception:
            pass
    return _numeric_values_close(actual, expected, tolerance)

def _sample_compare_mode(sample, sample_kind):
    raw = (sample.get("compare_mode") or sample.get("compare") or "").strip().lower().replace("-", "_").replace(" ", "_")
    if sample_kind == "script":
        return raw if raw in ("exact", "rstrip", "normalize_whitespace", "contains") else "rstrip"
    return raw if raw in ("exact", "numeric_tolerance", "contains") else "exact"

def _sample_tolerance(sample):
    value = sample.get("tolerance")
    if value in (None, ""):
        return 1e-6
    try:
        return max(float(value), 0.0)
    except Exception:
        return 1e-6

def _callable_result_matches(result_value, output_value, expected_text, compare_mode, expected_literal_defined, expected_literal, tolerance=None):
    if compare_mode == "contains":
        return _text_matches(output_value, expected_text, "contains"), ""
    if compare_mode == "numeric_tolerance":
        if not expected_literal_defined:
            return False, "Numeric tolerance comparison requires a literal expected value."
        return _values_close(result_value, expected_literal, tolerance), ""
    if expected_literal_defined:
        return _values_match(result_value, expected_literal), ""
    return _text_matches(output_value.strip(), expected_text.strip(), "exact"), ""

results = []
namespace = {"__name__": "__main__"}
setup_error = None

# ---------- Setup for callable modes ----------
if mode in ("function", "class"):
    try:
        _safe_exec(code, namespace, namespace, MAX_SETUP_OPS)
    except TimeLimitExceeded:
        setup_error = "Setup time limit exceeded."
    except Exception:
        setup_error = traceback.format_exc()

# ---------- Run samples ----------
for sample in samples:
    name = sample.get("name") or "Sample"

    if mode in ("function", "class"):
        call_expr = (sample.get("call") or sample.get("input") or "").strip()
        expected_output_display = (sample.get("expected") or sample.get("output") or "")
        expected_output = expected_output_display.strip()
        init_call = (sample.get("init_call") or "").strip() if mode == "class" else ""
        compare_mode = _sample_compare_mode(sample, "callable")
        tolerance = _sample_tolerance(sample) if compare_mode == "numeric_tolerance" else None
        expected_literal = None
        expected_literal_defined = False
        if expected_output:
            try:
                expected_literal = ast.literal_eval(expected_output)
                expected_literal_defined = True
            except Exception:
                expected_literal_defined = False

        status = "passed"
        error_text = ""
        output_value = ""
        result_value = None

        if not call_expr:
            status = "error"
            error_text = "Missing call expression."
        elif setup_error:
            status = "error"
            error_text = setup_error
        else:
            sample_ns = dict(namespace)
            stdout = io.StringIO()
            original_stdout = sys.stdout
            sys.stdout = stdout
            try:
                try:
                    if mode == "class":
                        if not init_call:
                            raise RuntimeError("Missing __init__ call.")
                        sample_ns["obj"] = _safe_eval(init_call, sample_ns, sample_ns, MAX_RUN_OPS)
                    result = _safe_eval(call_expr, sample_ns, sample_ns, MAX_RUN_OPS)
                    result_value = result
                    output_value = repr(result)
                except TimeLimitExceeded:
                    status = "timeout"
                    error_text = "Execution time limit exceeded."
                except Exception:
                    status = "error"
                    error_text = traceback.format_exc()
            finally:
                sys.stdout = original_stdout

        if status == "passed" and expected_output:
            matched, compare_error = _callable_result_matches(
                result_value,
                output_value,
                expected_output,
                compare_mode,
                expected_literal_defined,
                expected_literal,
                tolerance=tolerance,
            )
            if compare_error:
                status = "error"
                error_text = compare_error
            elif not matched:
                status = "mismatch"
        plot_images = _collect_plots()

        results.append({
            "name": name,
            "status": status,
            "input": call_expr,
            "output": output_value,
            "expected": expected_output_display,
            "error": error_text,
            "mode": mode,
            "init_call": init_call,
            "compare_mode": compare_mode,
            "tolerance": tolerance,
            "plot_images": plot_images,
        })

    else:
        # script / stdin mode
        sample_input = sample.get("input") or ""
        expected_output = sample.get("expected") or sample.get("output") or ""
        compare_mode = _sample_compare_mode(sample, "script")

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

        if status == "passed" and expected_output.strip() and not _text_matches(output_value, expected_output, compare_mode):
            status = "mismatch"
        plot_images = _collect_plots()

        results.append({
            "name": name,
            "status": status,
            "input": sample_input,
            "output": output_value,
            "expected": expected_output,
            "error": error_text,
            "mode": "script",
            "compare_mode": compare_mode,
            "tolerance": None,
            "plot_images": plot_images,
        })

json.dumps(results)
      `);
        return JSON.parse(output);
      } finally {
        pyodide.globals.delete("runner_code");
        pyodide.globals.delete("runner_samples");
        pyodide.globals.delete("runner_mode");
        clearHiddenMatplotlibTarget();
        listVisibleMatplotlibRoots().forEach((node) => {
          if (!existingVisibleRoots.has(node)) {
            node.remove();
          }
        });
        if (hadPreviousTarget) {
          document.pyodideMplTarget = previousTarget;
        } else {
          delete document.pyodideMplTarget;
        }
      }
    };
    const executePlotPreview = async (triggerBtn, codeValue) => {
      const results = await executeSamples(
        triggerBtn,
        [{ name: "Preview", input: "", expected: "" }],
        "script",
        codeValue,
      );
      return Array.isArray(results) ? results[0] || {} : {};
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
          const sanitized = parsed.map((entry) => {
            if (!entry || typeof entry !== "object") return entry;
            const { plot_images, ...rest } = entry;
            return rest;
          });
          postLog(questionId, sanitized);
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
        if (mode === "function" || mode === "class") {
          const callInput = root.querySelector(`[data-custom-call="${questionId}"]`);
          const callExpr = callInput ? callInput.value.trim() : "";
          if (!callExpr) {
            container.textContent = mode === "class"
              ? "Enter a method call or expression to run."
              : "Enter a function call to run.";
            return;
          }
          samples = [{
            name: "Custom run",
            call: callExpr,
            input: callExpr,
            expected: "",
            init_call: mode === "class" ? (btn.dataset.classInit || "") : "",
          }];
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

    plotButtons.forEach((btn) => {
      const questionId = btn.dataset.question;
      if (!questionId) return;
      attachPlotStaleTracker(questionId);
      syncPlotPreviewFromCache(questionId);
      btn.addEventListener("click", async () => {
        const area = root.querySelector(`[data-code-input="${questionId}"]`);
        if (!area) return;
        const originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = "Running...";
        setPlotSummary(questionId, "Running...", "#38bdf8");
        try {
          const entry = await executePlotPreview(btn, area.value || "");
          const plotImages = Array.isArray(entry.plot_images) ? entry.plot_images.filter(Boolean) : [];
          if (!plotImages.length) {
            revokePlotObjectUrl(questionId);
            plotRuntimeState.delete(questionId);
            if (artifactNamespace) {
              await deletePlotArtifact(artifactNamespace, questionId);
            }
            if (entry.error) {
              const preview = root.querySelector(`[data-plot-preview="${questionId}"]`);
              if (preview) {
                preview.innerHTML = `
                  <div style="display:flex; flex-direction:column; gap:8px;">
                    <p class="muted" style="margin:0;">No plot was generated.</p>
                    <pre style="white-space:pre-wrap; background:#1f2937; padding:8px; border-radius:8px; border:1px solid #334155;">${escapeHtml(entry.error)}</pre>
                  </div>
                `;
              }
              setPlotSummary(questionId, "Run failed", "#f87171");
            } else {
              renderPlotPreview(questionId, null, area.value || "");
              setPlotSummary(questionId, "No plot", "#fbbf24");
            }
            return;
          }

          const latest = plotImages[plotImages.length - 1];
          const record = {
            blob: base64ToBlob(latest, "image/png"),
            codeSnapshot: normalizeCodeText(area.value || ""),
            stdout: entry.output || "",
            error: entry.error || "",
            status: entry.status || "passed",
            plotCount: plotImages.length,
            updatedAt: new Date().toISOString(),
          };
          plotRuntimeState.set(questionId, record);
          if (artifactNamespace) {
            await savePlotArtifact(artifactNamespace, questionId, record);
          }
          renderPlotPreview(questionId, record, area.value || "");
        } catch (err) {
          const preview = root.querySelector(`[data-plot-preview="${questionId}"]`);
          if (preview) {
            preview.innerHTML = `<pre style="white-space:pre-wrap; background:#1f2937; padding:8px; border-radius:8px; border:1px solid #334155;">${escapeHtml(err.message || String(err))}</pre>`;
          }
          setPlotSummary(questionId, "Run failed", "#f87171");
        } finally {
          btn.disabled = false;
          btn.textContent = originalText;
        }
      });
    });

    if (form && artifactNamespace) {
      let replayingNativeSubmit = false;
      form.addEventListener("submit", async (event) => {
        if (replayingNativeSubmit) {
          replayingNativeSubmit = false;
          return;
        }
        const submitter = event.submitter;
        const artifacts = await getNamespaceArtifacts(artifactNamespace);
        if (!artifacts.length) {
          clearInjectedPlotFields();
          return;
        }
        event.preventDefault();
        const injected = injectPlotArtifactsIntoForm(artifacts);
        if (!injected) {
          clearInjectedPlotFields();
          replayingNativeSubmit = true;
          if (typeof form.requestSubmit === "function") {
            form.requestSubmit(submitter || undefined);
          } else {
            form.submit();
          }
          return;
        }
        replayingNativeSubmit = true;
        if (typeof form.requestSubmit === "function") {
          form.requestSubmit(submitter || undefined);
        } else {
          form.submit();
        }
      });
    }
  }

  function setupCodeEditors() {
    const codeAreas = Array.from(document.querySelectorAll("textarea[data-code-input]"));
    if (!codeAreas.length) return;
    const MONACO_ROOT = "https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min";
    const MONACO_BASE = `${MONACO_ROOT}/vs`;
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
              `self.MonacoEnvironment = { baseUrl: '${MONACO_ROOT}/' };`,
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

    const disablePaste = (editor, monaco) => {
      let lastValue = editor.getValue();
      const blockEvent = (evt) => {
        evt.preventDefault();
        evt.stopPropagation();
        return false;
      };
      editor.onKeyDown((evt) => {
        const key = evt.keyCode;
        if ((evt.ctrlKey || evt.metaKey) && key === monaco.KeyCode.KEY_V) {
          blockEvent(evt);
        }
        if (evt.shiftKey && key === monaco.KeyCode.Insert) {
          blockEvent(evt);
        }
      });
      const domNode = editor.getDomNode();
      const targets = [domNode, document, window].filter(Boolean);
      targets.forEach((t) => {
        ["paste", "drop", "contextmenu"].forEach((type) => t.addEventListener(type, blockEvent, true));
      });
      editor.onContextMenu((evt) => blockEvent(evt.event));
      editor.updateOptions({ contextmenu: false });
      editor.onDidChangeModelContent(() => {
        lastValue = editor.getValue();
      });
      editor.onDidPaste(() => {
        editor.setValue(lastValue);
      });
      ["editor.action.clipboardPasteAction", "editor.action.clipboardCopyAction", "editor.action.clipboardCutAction"].forEach((id) => {
        const action = editor.getAction(id);
        if (action && action.dispose) {
          action.dispose();
        }
      });
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
          area._monacoEditor = editor;
          disablePaste(editor, monaco);
          const syncValue = () => {
            area.value = editor.getValue();
            area.dispatchEvent(new Event("input", { bubbles: true }));
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
      typesetMath(preview);
    };
    areas.forEach((area) => {
      disableClipboardOnInput(area);
      render(area);
      area.addEventListener("input", () => render(area));
      area.addEventListener("change", () => render(area));
    });
  }

  function setupMarkdownStatic() {
    const blockSelectors = "[data-markdown-prompt], [data-markdown-statement], [data-markdown-instructions], [data-markdown-block]";
    const blocks = document.querySelectorAll(blockSelectors);
    blocks.forEach((block) => {
      const content = (block.textContent || "").trim();
      block.innerHTML = renderMarkdownText(content);
      block.style.whiteSpace = "normal";
      block.style.fontFamily = "system-ui, -apple-system, 'Segoe UI', sans-serif";
    });
    const inlineNodes = document.querySelectorAll("[data-markdown-inline]");
    inlineNodes.forEach((node) => {
      const content = node.textContent || "";
      node.innerHTML = renderMarkdownInline(content);
    });
    typesetMath();
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
