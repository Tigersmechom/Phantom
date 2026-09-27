'use strict';
const { contextBridge, ipcRenderer } = require('electron');
const invoke = (method, argument) => ipcRenderer.invoke('frame:request', method, argument);
const listen = (channel, listener) => {
  if (typeof listener !== 'function') throw new TypeError('Expected listener');
  const handler = (_event, value) => listener(value);
  ipcRenderer.on(channel, handler);
  return () => ipcRenderer.removeListener(channel, handler);
};
contextBridge.exposeInMainWorld('frameNative', {
  getWorkspace: () => invoke('getWorkspace'),
  openFile: () => invoke('openFile'),
  chooseWorkspace: () => invoke('chooseWorkspace'),
  saveDocument: request => invoke('saveDocument', request),
  updateDocumentState: request => invoke('updateDocumentState', request),
  saveBuildConfig: config => invoke('saveBuildConfig', config),
  revealBuildConfig: () => invoke('revealBuildConfig'),
  compile: request => invoke('compile', request),
  execute: request => invoke('execute', request),
  stopExecution: () => invoke('stopExecution'),
  onWorkspace: listener => listen('frame:workspace', listener),
  terminal: {
    open: dimensions => invoke('terminal.open', dimensions),
    restart: dimensions => invoke('terminal.restart', dimensions),
    write: request => invoke('terminal.write', request),
    resize: request => invoke('terminal.resize', request),
    onData: listener => listen('terminal:data', listener),
    onExit: listener => listen('terminal:exit', listener),
  },
});
