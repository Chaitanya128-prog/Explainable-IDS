const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let backendProcess = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    autoHideMenuBar: true,
    title: "Sentinel.AI - Real-time Network Intelligence"
  });

  // Load static React build if bundled, else fallback
  if (app.isPackaged) {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.on('closed', function () {
    mainWindow = null;
  });
}

function startBackend() {
  const backendPath = app.isPackaged 
    ? path.join(process.resourcesPath, 'backend.exe') 
    : path.join(__dirname, '..', 'backend', 'dist', 'SentinelBackend.exe');

  console.log("Starting backend from:", backendPath);
  
  try {
    backendProcess = spawn(backendPath, [], {
      detached: false,
      windowsHide: true   // Hide the terminal popup
    });

    backendProcess.stdout.on('data', (data) => console.log(`Backend: ${data}`));
    backendProcess.stderr.on('data', (data) => console.error(`Backend Err: ${data}`));
  } catch (e) {
    console.error("Failed to start backend:", e);
  }
}

app.on('ready', () => {
  startBackend();
  // Wait 3 seconds for the heavy PyInstaller FastAPI bundle to initialize Uvicorn
  setTimeout(createWindow, 3000); 
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('will-quit', () => {
  // Slay the background AI network sniffer when the UI closes
  if (backendProcess) {
    backendProcess.kill();
  }
  spawn("taskkill", ["/F", "/IM", "SentinelBackend.exe"], { windowsHide: true });
  spawn("taskkill", ["/F", "/IM", "backend.exe"], { windowsHide: true });
});
