import type { JupyterFrontEnd, JupyterFrontEndPlugin } from '@jupyterlab/application';
import { INotebookTracker, NotebookPanel } from '@jupyterlab/notebook';
import { IDocumentManager } from '@jupyterlab/docmanager';
import { DocumentRegistry } from '@jupyterlab/docregistry';
import { ToolbarButton } from '@jupyterlab/apputils';
import type * as nbformat from '@jupyterlab/nbformat';

// Top-level log so you can verify the bundle actually loads
console.log('[chalk] plugin bundle loaded');

/** Server helpers */
async function getCSRF(): Promise<string> {
  const res = await fetch('/api/csrf', { credentials: 'same-origin' });
  const j = await res.json();
  return j.csrf as string;
}

async function getMe(): Promise<{ id: number; name?: string } | null> {
  const res = await fetch('/api/me', { credentials: 'same-origin' });
  if (!res.ok) return null;
  return res.json();
}

/**
 * HARD per-user isolation:
 * If a new student logs in on the same browser, nuke all JupyterLite storage
 * (IndexedDB, caches, local/session storage keys), then reload once.
 */
async function ensurePerUserStorage(): Promise<void> {
  const me = await getMe();
  if (!me) return;

  const KEY = 'chalk_student_id_v2';
  const prev = window.localStorage.getItem(KEY);
  const now = String(me.id);

  if (prev === now) return;

  // 1) IndexedDB
  try {
    const anyIDB = indexedDB as any;
    if (typeof anyIDB.databases === 'function') {
      const dbs: Array<{ name?: string }> = await anyIDB.databases();
      for (const db of dbs) {
        if (db.name) {
          await new Promise<void>((resolve) => {
            const req = indexedDB.deleteDatabase(db.name as string);
            req.onsuccess = () => resolve();
            req.onerror = () => resolve();
            req.onblocked = () => resolve();
          });
        }
      }
    } else {
      const common = [
        'JupyterLite Storage',
        'JupyterLite v1',
        'JupyterLite',
        'JupyterLite Contents',
        'JupyterLab Workspaces',
        'jupyterlite',
        'jp-contents'
      ];
      for (const name of common) {
        await new Promise<void>((resolve) => {
          const req = indexedDB.deleteDatabase(name);
          req.onsuccess = () => resolve();
          req.onerror = () => resolve();
          req.onblocked = () => resolve();
        });
      }
    }
  } catch { /* ignore */ }

  // 2) Cache Storage
  try {
    if ('caches' in window) {
      const keys = await caches.keys();
      for (const k of keys) {
        if (k.toLowerCase().includes('jupyter')) {
          await caches.delete(k).catch(() => {});
        }
      }
    }
  } catch { /* ignore */ }

  // 3) local/session storage keys
  try {
    for (const k of Object.keys(localStorage)) {
      if (/jupyter|jp-|jupyterlab|jupyterlite/i.test(k)) localStorage.removeItem(k);
    }
    for (const k of Object.keys(sessionStorage)) {
      if (/jupyter|jp-|jupyterlab|jupyterlite/i.test(k)) sessionStorage.removeItem(k);
    }
  } catch { /* ignore */ }

  window.localStorage.setItem(KEY, now);
  window.location.reload();
}

/** Notebook JSON helpers */
function getNotebookJSON(panel: NotebookPanel): nbformat.INotebookContent | null {
  const raw = panel.context.model.toJSON() as unknown;
  if (!raw || typeof raw !== 'object') return null;
  return raw as nbformat.INotebookContent;
}

/** Save to server: create once, then update the same row (chalk_id in metadata). */
async function saveToServer(panel: NotebookPanel): Promise<void> {
  const nb = getNotebookJSON(panel);
  if (!nb) {
    console.warn('[chalk] Could not read notebook JSON');
    return;
  }
  const csrf = await getCSRF();

  const md = (nb.metadata ?? {}) as any;
  const chalkId: number | undefined = md.chalk_id;

  if (!chalkId) {
    const resp = await fetch('/api/notebooks', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': csrf },
      credentials: 'same-origin',
      body: JSON.stringify({ content: nb })
    });
    if (!resp.ok) throw new Error(`Create failed: ${resp.status}`);
    const data = await resp.json();
    md.chalk_id = data.id;
    nb.metadata = md;
    panel.context.model.fromJSON(nb);
    await panel.context.save();
    console.log('[chalk] created notebook id', data.id);
  } else {
    const resp = await fetch(`/api/notebooks/${chalkId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-CSRF': csrf },
      credentials: 'same-origin',
      body: JSON.stringify({ content: nb })
    });
    if (!resp.ok) throw new Error(`Update failed: ${resp.status}`);
    console.log('[chalk] updated notebook id', chalkId);
  }
}

/** Import from server when URL has #import=<id> (student-scoped server API). */
async function importFromServer(app: JupyterFrontEnd, docManager: IDocumentManager): Promise<void> {
  const hash = window.location.hash || '';
  const m = hash.match(/#.*\bimport=(\d+)/);
  if (!m) return;
  const id = parseInt(m[1], 10);
  if (!id) return;

  const res = await fetch(`/api/notebooks/${id}`, { credentials: 'same-origin' });
  if (!res.ok) {
    alert('Could not load notebook from server.');
    return;
  }
  const data = await res.json();
  const nb = data.content as nbformat.INotebookContent;

  const md = (nb.metadata ?? {}) as any;
  // IMPORTANT: Set chalk_id so subsequent saves update the same notebook instead of creating duplicates
  md.chalk_id = id;
  nb.metadata = md;

  const name = `imported-${id}.ipynb`;
  await app.serviceManager.contents.save(name, { type: 'notebook', format: 'json', content: nb });
  await docManager.openOrReveal(name);
  console.log('[chalk] imported notebook', id);
}

const plugin: JupyterFrontEndPlugin<void> = {
  id: 'chalk-lite-sync',
  autoStart: true,
  requires: [INotebookTracker, IDocumentManager],
  activate: (app: JupyterFrontEnd, tracker: INotebookTracker, docManager: IDocumentManager) => {
    console.log('[chalk] lite sync plugin started');

    void ensurePerUserStorage()
      .then(() => importFromServer(app, docManager))
      .catch(err => console.error('[chalk] ensurePerUserStorage/import error', err));

    tracker.widgetAdded.connect((_sender: INotebookTracker, panel: NotebookPanel) => {
      const button = new ToolbarButton({
        label: 'Save to Server',
        tooltip: 'Save notebook to Chalk & Choice',
        onClick: () => {
          void saveToServer(panel).catch(err => {
            console.error(err);
            alert('Save failed');
          });
        }
      });
      panel.toolbar.addItem('chalkSave', button);

      panel.context.saveState.connect((_ctx: DocumentRegistry.Context, state: DocumentRegistry.SaveState) => {
        if (state === 'completed') {
          window.setTimeout(() => { void saveToServer(panel).catch(console.error); }, 100);
        }
      });
    });
  }
};

export default [plugin];
