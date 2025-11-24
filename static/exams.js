(function () {
  const randomId = () => "q" + Math.random().toString(36).slice(2, 9);

  function setupExamBuilder() {
    const root = document.querySelector("[data-exam-builder]");
    if (!root) return;
    const list = root.querySelector("[data-question-list]");
    const addBtn = root.querySelector("[data-add-question]");
    const typeSelect = root.querySelector("[data-question-type]");
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
        const container = target.closest("[data-question-id]")?.querySelector("[data-sample-list]");
        if (container) {
          container.appendChild(buildSampleRow());
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

      const sampleHeader = document.createElement("div");
      sampleHeader.className = "row";
      sampleHeader.style.justifyContent = "space-between";
      sampleHeader.style.alignItems = "center";
      sampleHeader.style.marginTop = "10px";
      sampleHeader.innerHTML = `<strong>Samples</strong>
        <button type="button" class="btn" data-action="add-sample">Add sample</button>`;
      card.appendChild(sampleHeader);

      const sampleList = document.createElement("div");
      sampleList.dataset.sampleList = "1";
      sampleList.setAttribute("data-sample-list", "1");
      sampleList.style.display = "flex";
      sampleList.style.flexDirection = "column";
      sampleList.style.gap = "10px";
      card.appendChild(sampleList);

      const samples = Array.isArray(data.samples) && data.samples.length ? data.samples : [{}];
      samples.forEach((sample) => {
        sampleList.appendChild(buildSampleRow(sample));
      });
    }

    return card;
  }

  function buildSampleRow(sample = {}) {
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
        payload.statement = getFieldValue(card, "statement");
        payload.starter = getFieldValue(card, "starter");
        payload.samples = Array.from(card.querySelectorAll("[data-sample-row]")).map((row) => ({
          name: getFieldValue(row, "sample-name"),
          input: getFieldValue(row, "sample-input"),
          output: getFieldValue(row, "sample-output"),
        }));
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
          <div style="margin-top:4px;">
            <div class="muted">Output</div>
            <pre style="white-space:pre-wrap; background:#0b1220; padding:6px; border-radius:6px;">${escapeHtml(sample.output || "")}</pre>
          </div>
          <div style="margin-top:4px;">
            <div class="muted">Expected</div>
            <pre style="white-space:pre-wrap; background:#0b1220; padding:6px; border-radius:6px;">${escapeHtml(sample.expected || "")}</pre>
          </div>
        `;
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
          const output = await pyodide.runPythonAsync(`
import io, sys, traceback, json, builtins
code = str(runner_code)
samples = runner_samples.to_py()
results = []
for sample in samples:
    name = sample.get("name") or "Sample"
    stdin = io.StringIO(sample.get("input") or "")
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
    except Exception as exc:
        status = "error"
        error_text = traceback.format_exc()
    finally:
        sys.stdout = original_stdout
        sys.stdin = original_stdin
        builtins.input = original_input
    results.append({
        "name": name,
        "status": status,
        "output": stdout.getvalue(),
        "expected": sample.get("output") or "",
        "error": error_text,
    })
json.dumps(results)
          `);
          pyodide.globals.delete("runner_code");
          pyodide.globals.delete("runner_samples");
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
