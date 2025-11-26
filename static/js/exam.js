'use strict';
class ExamInterface {
  constructor(code, csrf){
    this.code = code;
    this.csrf = csrf;
    this.meta = null;
    this.current = 1;
    this.total = 0;
    this.executor = null;
    this.editor = null;
    this.editorReady = false;
    this.loadingEditor = false;
  }
  showLoading(text){
    const ov = document.getElementById('loading-overlay');
    const tx = document.getElementById('loading-text');
    if(ov){ ov.style.display = 'flex'; }
    if(tx){ tx.textContent = text || 'Loading…'; }
  }
  updateLoading(text){
    const tx = document.getElementById('loading-text');
    if(tx){ tx.textContent = text || 'Loading…'; }
  }
  hideLoading(){
    const ov = document.getElementById('loading-overlay');
    if(ov){ ov.style.display = 'none'; }
  }
  async initialize(){
    this.showLoading('Loading exam…');
    const r = await fetch(`/api/exam/${this.code}/meta`);
    if(!r.ok) throw new Error('Failed to load exam');
    this.meta = await r.json();
    this.total = (this.meta.questions||[]).length;
    this.renderNav();
    await this.goto(1);
    this.hideLoading();
    document.getElementById('prev-q')?.addEventListener('click', ()=> this.goto(Math.max(1, this.current-1)));
    document.getElementById('next-q')?.addEventListener('click', ()=> {
      if(this.current >= this.total){ this.submitExam(true); } else { this.goto(this.current+1); }
    });
    document.getElementById('submit-exam')?.addEventListener('click', ()=> this.submitExam(false));
  }
  renderNav(){
    const wrap = document.getElementById('q-nav');
    if(!wrap) return;
    wrap.innerHTML = '';
    (this.meta.questions||[]).forEach((q)=>{
      const b = document.createElement('button');
      b.className = 'q-btn';
      b.textContent = String(q.order);
      b.addEventListener('click', ()=> this.goto(q.order));
      b.dataset.order = String(q.order);
      wrap.appendChild(b);
    });
  }
  setActiveNav(order){
    document.querySelectorAll('.q-btn').forEach(el=>{
      if(el instanceof HTMLElement){
        if(el.dataset.order === String(order)) el.classList.add('active'); else el.classList.remove('active');
      }
    });
  }
  markAnswered(order, answered){
    const btn = document.querySelector(`.q-btn[data-order="${order}"]`);
    if(btn){
      if(answered) btn.classList.add('answered'); else btn.classList.remove('answered');
    }
  }
  async goto(order){
    this.current = order;
    this.setActiveNav(order);
    this.showLoading('Loading question…');
    const r = await fetch(`/api/exam/${this.code}/question/${order}`);
    if(!r.ok){ this.hideLoading(); throw new Error('Failed to load question'); }
    const q = await r.json();
    const right = document.getElementById('right-pane');
    const pointsEl = document.getElementById('points');
    document.getElementById('score-line').textContent = '';
    const promptEl = document.getElementById('q-prompt');
    if(q.type === 'mcq'){
      promptEl.textContent = q.prompt || '';
      document.getElementById('q-title').textContent = `Question ${q.order}`;
      if(right) right.style.display = 'none';
      if(pointsEl){ pointsEl.textContent = ''; pointsEl.style.display = 'none'; }
      this.renderMCQ(q);
      this.hideLoading();
      const sel = (q.answer && q.answer.selected) ? q.answer.selected : [];
      this.markAnswered(order, sel.length > 0);
    } else {
      this.updateLoading('Preparing code environment…');
      if (typeof marked !== 'undefined') { promptEl.innerHTML = marked.parse(q.prompt || ''); }
      else { promptEl.textContent = q.prompt || ''; }
      document.getElementById('q-title').textContent = q.title || 'Code Problem';
      if(right) right.style.display = 'block';
      if(pointsEl){ pointsEl.textContent = `${q.points} points`; pointsEl.style.display = 'block'; }
      this.updateLoading('Initializing Python runtime…');
      await this.ensureExecutor();
      this.updateLoading('Loading editor…');
      await this.ensureEditor();
      await this.renderCode(q);
      this.hideLoading();
      const hasCode = !!(q.answer && q.answer.code && q.answer.code.trim());
      this.markAnswered(order, hasCode);
    }
    this.updateNavControls();
  }
  updateNavControls(){
    const prev = document.getElementById('prev-q');
    const next = document.getElementById('next-q');
    if(prev){ prev.disabled = (this.current <= 1); }
    if(next){ next.textContent = (this.current >= this.total) ? 'Finish' : 'Next'; }
  }
  renderMCQ(q){
    const mcq = document.getElementById('mcq-area');
    const code = document.getElementById('code-area');
    mcq.style.display = 'block';
    code.style.display = 'none';
    mcq.innerHTML = '';
    const optsWrap = document.createElement('div');
    const selected = (q.answer && q.answer.selected) ? q.answer.selected : [];
    const inputType = q.multiple ? 'checkbox' : 'radio';
    (q.options||[]).forEach((opt, idx)=>{
      const row = document.createElement('label');
      row.className = 'mcq-opt';
      const input = document.createElement('input');
      input.type = inputType;
      input.name = 'mcq';
      input.value = String(idx);
      if(selected.includes(idx)) { input.checked = true; row.classList.add('selected'); }
      const span = document.createElement('span');
      span.textContent = opt;
      row.appendChild(input);
      row.appendChild(span);
      input.addEventListener('change', ()=>{
        if(inputType === 'radio'){
          // Clear all, then set this
          optsWrap.querySelectorAll('.mcq-opt').forEach(r=> r.classList.remove('selected'));
          if(input.checked) row.classList.add('selected');
        } else {
          // Toggle for checkbox
          if(input.checked) row.classList.add('selected'); else row.classList.remove('selected');
        }
        const picks = [];
        optsWrap.querySelectorAll('input').forEach(el=>{ if(el instanceof HTMLInputElement){ if(el.checked) picks.push(parseInt(el.value,10)); }});
        this.markAnswered(this.current, picks.length > 0);
      });
      optsWrap.appendChild(row);
    });
    const actions = document.createElement('div');
    actions.className = 'actions';
    const save = document.createElement('button');
    save.className = 'btn-primary';
    save.textContent = 'Save Answer';
    const status = document.createElement('div');
    status.className = 'status';
    status.style.marginLeft = '8px';
    save.addEventListener('click', async ()=>{
      const picks = [];
      optsWrap.querySelectorAll('input').forEach(el=>{ if(el instanceof HTMLInputElement){ if(el.checked) picks.push(parseInt(el.value,10)); }});
      status.textContent = 'Saving…';
      save.disabled = true;
      try{
        const resp = await fetch(`/api/exam/${this.code}/answer/${this.current}`, { method:'POST', headers:{ 'Content-Type':'application/json', 'X-CSRF': window.__EXAM__.csrf }, body: JSON.stringify({ selected: picks }) });
        if(resp.ok){ status.textContent = 'Answer saved'; }
        else { status.textContent = 'Failed to save'; }
      }catch(e){ status.textContent = 'Failed to save'; }
      finally{ save.disabled = false; }
      this.markAnswered(this.current, picks.length > 0);
    });
    actions.appendChild(save);
    actions.appendChild(status);
    mcq.appendChild(optsWrap);
    mcq.appendChild(actions);
  }
  async ensureExecutor(){
    if(!this.executor){ this.executor = new CodeExecutor(); }
    if(!this.executor.isReady){ await this.executor.initialize(); }
  }
  async ensureEditor(){
    if(this.editorReady) return;
    if(this.loadingEditor) { while(this.loadingEditor) { await new Promise(r=>setTimeout(r,50)); } return; }
    this.loadingEditor = true;
    await new Promise((resolve, reject)=>{
      if(typeof require === 'undefined'){
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js';
        s.onload = ()=> this._loadMonaco(resolve, reject);
        s.onerror = ()=> reject(new Error('Failed to load Monaco loader'));
        document.head.appendChild(s);
      } else {
        this._loadMonaco(resolve, reject);
      }
    });
    this.editorReady = true;
    this.loadingEditor = false;
  }
  _loadMonaco(resolve, reject){
    require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' } });
    require(['vs/editor/editor.main'], ()=>{
      try{
        const el = document.getElementById('code-editor');
        this.editor = monaco.editor.create(el, { value: '# Write your code here\n', language: 'python', theme: 'vs-dark', automaticLayout: true, minimap:{enabled:false}, fontSize:14, wordWrap:'on' });
        resolve();
      }catch(e){ reject(e); }
    }, (e)=> reject(new Error('Failed to load Monaco: '+e)));
  }
  async renderCode(q){
    const mcq = document.getElementById('mcq-area');
    const code = document.getElementById('code-area');
    mcq.style.display = 'none';
    code.style.display = 'block';
    const editorVal = (q.answer && q.answer.code) ? q.answer.code : (q.starter_code || '# Write your code here\n');
    this.editor.setValue(editorVal);
    const inputWrap = document.getElementById('input-wrap');
    inputWrap.style.display = 'block';
    const inputArea = document.getElementById('custom-input');
    inputArea.value = q.default_input || '';
    inputArea.dataset.default = q.default_input || '';
    const out = document.getElementById('output-display');
    const t = document.getElementById('exec-time');
    const testsDiv = document.getElementById('test-results');
    testsDiv.style.display = 'none';
    const runTestsBtn = document.getElementById('run-tests');
    if(runTestsBtn){
      const hasVisible = Array.isArray(q.visible_test_cases) && q.visible_test_cases.length > 0;
      runTestsBtn.disabled = !hasVisible;
      runTestsBtn.title = hasVisible ? '' : 'No tests attached';
    }
    document.getElementById('run-code').onclick = async ()=>{
      out.textContent = 'Running...'; t.textContent = '';
      const res = await this.executor.runCode(this.editor.getValue(), inputArea.value);
      if(res.success){ out.textContent = res.output || '(no output)'; t.textContent = `Executed in ${res.executionTime}ms`; }
      else { out.textContent = 'Error\n'+res.error; t.textContent = `Failed after ${res.executionTime}ms`; }
    };
    document.getElementById('run-tests').onclick = async ()=>{
      testsDiv.style.display = 'block'; testsDiv.innerHTML = 'Running tests...';
      const resp = await fetch(`/api/exam/${this.code}/question/${this.current}/all-tests`);
      if(!resp.ok){ testsDiv.textContent = 'Failed to load tests'; return; }
      const data = await resp.json();
      if(!data.test_cases || data.test_cases.length === 0){
        testsDiv.textContent = 'No tests attached for this question.';
        return;
      }
      const results = await this.executor.runTestCases(this.editor.getValue(), data.test_cases || []);
      const visible = results.filter(r=> ! (data.test_cases[r.test_num-1]||{}).hidden);
      testsDiv.innerHTML = visible.map(r=>`<div class="mcq-opt ${r.passed?'ok':''}">Test ${r.test_num}: ${r.passed?'✓':'✗'}</div>`).join('');
    };
    document.getElementById('save-code-answer').onclick = async ()=>{
      const resp = await fetch(`/api/exam/${this.code}/question/${this.current}/all-tests`);
      if(!resp.ok){ return; }
      const data = await resp.json();
      const results = await this.executor.runTestCases(this.editor.getValue(), data.test_cases || []);
      const r2 = await fetch(`/api/exam/${this.code}/answer/${this.current}`, { method:'POST', headers:{ 'Content-Type':'application/json', 'X-CSRF': window.__EXAM__.csrf }, body: JSON.stringify({ code: this.editor.getValue(), test_results: results }) });
      if(r2.ok){ document.getElementById('score-line').textContent = 'Answer saved'; }
      this.markAnswered(this.current, (this.editor.getValue().trim().length > 0));
    };
    document.getElementById('reset-code').onclick = ()=>{ this.editor.setValue(q.starter_code || '# Write your code here\n'); };
  }
  async submitExam(auto=false){
    if(!auto){ if(!confirm('Submit exam?')) return; }
    const r = await fetch(`/api/exam/${this.code}/submit`, { method:'POST', headers:{ 'X-CSRF': this.csrf } });
    if(r.ok){ window.location.href = '/'; }
  }
}
(function(){
  const cfg = window.__EXAM__ || {};
  const ui = new ExamInterface(cfg.code, cfg.csrf);
  ui.initialize().catch(e=>{ alert('Failed to initialize exam: '+e.message); });
})();
