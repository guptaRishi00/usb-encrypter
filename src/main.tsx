import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import App from './App';
import { FolderPopup } from './pages/FolderPopup';
import { popupInfo } from './services/api';
import './styles/global.css';

const root = document.getElementById('root');
if (!root) throw new Error('#root is missing from index.html');

// A right-click menu in a desktop shell offers Reload and View Source, which
// are not features of this application. Text selection inside inputs and
// previews still works.
document.addEventListener('contextmenu', (e) => {
  const target = e.target as HTMLElement | null;
  if (target?.closest('input, textarea, .selectable')) return;
  e.preventDefault();
});

// The program inside a locked folder opens a small popup for that folder
// instead of the full application. Ask before the first render, so neither
// flashes up in place of the other.
void popupInfo()
  .catch(() => null)
  .then((info) => {
    createRoot(root).render(
      <StrictMode>{info ? <FolderPopup info={info} /> : <App />}</StrictMode>,
    );
  });
