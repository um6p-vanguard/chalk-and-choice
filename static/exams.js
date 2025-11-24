(function () {
  const randomId = () => "q" + Math.random().toString(36).slice(2, 9);

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

    const promptLabel = document.createElement("label");
    promptLabel.textContent = "Prompt";
    card.appendChild(promptLabel);
    const prompt = document.createElement("textarea");
    prompt.dataset.field = "prompt";
    prompt.rows = 3;
    prompt.value = data.prompt || "";
    card.appendChild(prompt);

    if (type === "mcq") {
      const optionsLabel = document.createElement("label");
      optionsLabel.textContent = "Options (one per line)";
      card.appendChild(optionsLabel);
      const options = document.createElement("textarea");
      options.dataset.field = "options";
      options.rows = 4;
      options.placeholder = "Option A\nOption B\nOption C";
      options.value = Array.isArray(data.options) ? data.options.join("\n") : (data.options || "");
      card.appendChild(options);
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
    }

    return card;
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
      if (type === "mcq") {
        const optionsText = getFieldValue(card, "options");
        payload.options = optionsText.split("\n").map((v) => v.trim()).filter(Boolean);
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
          }));
        } else {
          const rows = card.querySelectorAll('[data-sample-list="script"] [data-sample-row]');
          payload.samples = Array.from(rows).map((row) => ({
            name: getFieldValue(row, "sample-name"),
            input: getFieldValue(row, "sample-input"),
            output: getFieldValue(row, "sample-output"),
          }));
        }
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
    if (!buttons.length) return;
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

    const renderResults = (container, results) => {
      container.innerHTML = "";
      results.forEach((sample) => {
        const block = document.createElement("div");
        block.style.borderTop = "1px solid #1f2937";
        block.style.paddingTop = "6px";
        block.style.marginTop = "6px";
        const statusColor = sample.status === "passed" ? "#4ade80" : "#f87171";
        block.innerHTML = `
          <strong>${sample.name || "Sample"}</strong>
          <span style="color:${statusColor}; margin-left:8px;">${sample.status}</span>
        `;

        const splitRow = document.createElement("div");
        splitRow.style.display = "flex";
        splitRow.style.flexWrap = "wrap";
        splitRow.style.gap = "12px";
        splitRow.style.marginTop = "8px";

        const leftCol = document.createElement("div");
        leftCol.style.flex = "1 1 240px";
        leftCol.innerHTML = `
          <div class="muted">Input</div>
          <pre style="white-space:pre-wrap; background:#0b1220; padding:6px; border-radius:6px; min-height:66px;">${escapeHtml(sample.input || "")}</pre>
        `;

        const rightCol = document.createElement("div");
        rightCol.style.flex = "1 1 240px";
        rightCol.innerHTML = `
          <div style="margin-bottom:6px;">
            <div class="muted">Your output</div>
            <pre style="white-space:pre-wrap; background:#0b1220; padding:6px; border-radius:6px; min-height:66px;">${escapeHtml(sample.output || "")}</pre>
          </div>
          <div>
            <div class="muted">Expected output</div>
            <pre style="white-space:pre-wrap; background:#0b1220; padding:6px; border-radius:6px; min-height:66px;">${escapeHtml(sample.expected || "")}</pre>
          </div>
        `;

        splitRow.appendChild(leftCol);
        splitRow.appendChild(rightCol);
        block.appendChild(splitRow);

        if (sample.error) {
          const errBlock = document.createElement("pre");
          errBlock.textContent = sample.error;
          errBlock.style.background = "#1f2937";
          errBlock.style.padding = "6px";
          errBlock.style.borderRadius = "6px";
          errBlock.style.marginTop = "6px";
          block.appendChild(errBlock);
        }
        container.appendChild(block);
      });
    };

    const escapeHtml = (str) => {
      return (str || "").replace(/[&<>"']/g, (char) => {
        const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
        return map[char] || char;
      });
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
          const pyodide = await ensurePyodide();
          pyodide.globals.set("runner_code", codeArea.value);
          pyodide.globals.set("runner_samples", samples);
          pyodide.globals.set("runner_mode", btn.getAttribute("data-mode") || "script");
          const output = await pyodide.runPythonAsync(`
import io, sys, traceback, json, builtins
code = str(runner_code)
samples = runner_samples.to_py()
mode = str(runner_mode)
results = []
namespace = {}
setup_error = None
if mode == "function":
    try:
        exec(code, namespace, namespace)
    except Exception:
        setup_error = traceback.format_exc()
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
                result = eval(call_expr, namespace, namespace)
                output_value = repr(result)
            except Exception:
                status = "error"
                error_text = traceback.format_exc()
            finally:
                sys.stdout = original_stdout
        if status == "passed" and output_value.strip() != expected_output.strip():
            status = "mismatch"
        results.append({
            "name": name,
            "status": status,
            "input": call_expr,
            "output": output_value,
            "expected": expected_output,
            "error": error_text,
        })
    else:
        sample_input = sample.get("input") or ""
        expected_output = sample.get("output") or ""
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
            exec(code, {"__name__": "__main__"})
        except Exception:
            status = "error"
            error_text = traceback.format_exc()
        finally:
            sys.stdout = original_stdout
            sys.stdin = original_stdin
            builtins.input = original_input
        output_value = stdout.getvalue()
        if status == "passed" and output_value.strip() != expected_output.strip():
            status = "mismatch"
        results.append({
            "name": name,
            "status": status,
            "input": sample_input,
            "output": output_value,
            "expected": expected_output,
            "error": error_text,
        })
json.dumps(results)
          `);
          pyodide.globals.delete("runner_code");
          pyodide.globals.delete("runner_samples");
          pyodide.globals.delete("runner_mode");
          const parsed = JSON.parse(output);
          renderResults(resultsContainer, parsed);
          postLog(questionId, parsed);
        } catch (err) {
          console.error(err);
          resultsContainer.textContent = `Unable to run samples: ${err.message || err}`;
        } finally {
          btn.disabled = false;
          btn.textContent = originalText;
        }
      });
    });
  }

  setupExamBuilder();
  setupExamRunner();
})();
