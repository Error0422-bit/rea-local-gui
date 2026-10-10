import os
import queue
import threading
import tkinter as tk

from pathlib import Path
from tkinter import ttk, filedialog, messagebox, scrolledtext
from analysis_core import analyze, engine_status, REPORTS
from full_decompile import analyze_with_mode
from export_pseudocode import open_export_dialog

class Application:
    def __init__(self, root):
        self.root = root
        self.root.title("REA Universal Analyzer V2")
        self.root.geometry("980x720")
        self.root.minsize(750, 540)

        self.targets = []
        self.events = queue.Queue()
        self.latest = None
        self.running = False

        frame = ttk.Frame(root, padding=15)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="REA 通用静态分析器 V2",
            font=("Microsoft YaHei UI", 18, "bold")
        ).pack(anchor="w", pady=5)

        ttk.Label(
            frame,
            text="自动识别文件格式，按类型调用专业分析引擎"
        ).pack(anchor="w", pady=5)

        toolbar = ttk.Frame(frame)
        toolbar.pack(fill="x", pady=10)

        actions = [
            ("添加文件", self.add_files),
            ("添加文件夹", self.add_folder),
            ("移除选中", self.remove_selected),
            ("检查引擎", self.check_engines),
            ("打开报告目录", self.open_reports),
            ("复制摘要", self.copy_summary)
        ]

        for label, action in actions:
            ttk.Button(
                toolbar,
                text=label,
                command=action
            ).pack(side="left", padx=3)

        self.file_list = tk.Listbox(
            frame,
            height=7,
            selectmode="extended"
        )
        self.file_list.pack(fill="x", pady=8)

        controls = ttk.Frame(frame)
        controls.pack(fill="x", pady=8)

        self.mode = tk.StringVar(value='quick')
        ttk.Radiobutton(controls, text='快速分析', variable=self.mode, value='quick').pack(side='left', padx=5)
        ttk.Radiobutton(controls, text='尽可能完整反编译', variable=self.mode, value='full').pack(side='left', padx=5)
        self.export_code_button = ttk.Button(
            controls, text='导出伪代码 (.c)',
            command=lambda: open_export_dialog(self)
        )
        self.export_code_button.pack(side='left', padx=5)
        self.start_button = ttk.Button(
            controls,
            text="开始自动分析",
            command=self.start
        )
        self.start_button.pack(side="left")

        self.progress = ttk.Progressbar(
            controls,
            mode="indeterminate"
        )
        self.progress.pack(
            side="left",
            fill="x",
            expand=True,
            padx=15
        )

        self.status_label = ttk.Label(
            frame,
            text="准备就绪"
        )
        self.status_label.pack(anchor="w", pady=7)

        ttk.Label(
            frame,
            text="执行日志 / Markdown 报告预览"
        ).pack(anchor="w")

        self.textbox = scrolledtext.ScrolledText(
            frame,
            wrap="word",
            font=("Consolas", 10)
        )
        self.textbox.pack(
            fill="both",
            expand=True,
            pady=8
        )

        self.root.after(120, self.process_events)

    def add_target(self, path):
        if not path:
            return

        path = str(Path(path).resolve())

        if path not in self.targets:
            self.targets.append(path)
            self.file_list.insert("end", path)

    def add_files(self):
        for path in filedialog.askopenfilenames():
            self.add_target(path)

    def add_folder(self):
        self.add_target(filedialog.askdirectory())

    def remove_selected(self):
        for index in reversed(self.file_list.curselection()):
            self.file_list.delete(index)
            self.targets.pop(index)

    def check_engines(self):
        results = engine_status()

        message = "\n".join(
            name + ": " + (
                "已检测到" if enabled else "未安装或未配置"
            )
            for name, enabled in results.items()
        )

        message += "\n\n检测到不等于已通过真实分析测试。"
        messagebox.showinfo("分析引擎状态", message)

    def start(self):
        if self.running:
            return

        if not self.targets:
            messagebox.showwarning(
                "提示", "请先添加文件或文件夹"
            )
            return

        self.run_mode = self.mode.get()
        self.running = True
        self.latest = None
        self.start_button.configure(state="disabled")
        self.textbox.delete("1.0", "end")
        self.progress.start(15)
        self.status_label.configure(text="分析中...")

        threading.Thread(
            target=self.worker,
            args=(list(self.targets),),
            daemon=True
        ).start()

    def worker(self, targets):
        for path in targets:
            try:
                report, record = analyze_with_mode(self.run_mode, 
                    path,
                    lambda text: self.events.put(("log", text))
                )

                self.events.put((
                    "report",
                    (report, record["status"])
                ))

            except Exception as exc:
                self.events.put((
                    "log",
                    "分析失败: " + str(exc)
                ))

        self.events.put(("done", None))

    def process_events(self):
        try:
            while True:
                event, value = self.events.get_nowait()

                if event == "log":
                    self.textbox.insert(
                        "end", str(value) + "\n"
                    )

                elif event == "report":
                    report, result_status = value
                    self.latest = report

                    self.textbox.insert(
                        "end",
                        "\n" + report.read_text(
                            encoding="utf-8"
                        )[:30000] + "\n"
                    )
                    self.status_label.configure(
                        text="已生成报告: " + result_status
                    )

                elif event == "done":
                    self.running = False
                    self.progress.stop()
                    self.start_button.configure(
                        state="normal"
                    )
                    self.status_label.configure(
                        text="本轮分析结束，请检查各引擎状态"
                    )

                self.textbox.see("end")

        except queue.Empty:
            pass

        self.root.after(120, self.process_events)

    def copy_summary(self):
        if self.latest is None:
            messagebox.showwarning(
                "提示", "还没有生成分析报告"
            )
            return

        content = self.latest.read_text(
            encoding="utf-8"
        )

        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.root.update()

        messagebox.showinfo(
            "完成", "Markdown 报告已复制"
        )

    def open_reports(self):
        folder = (
            self.latest.parent
            if self.latest is not None
            else REPORTS
        )
        folder.mkdir(parents=True, exist_ok=True)
        os.startfile(str(folder))

def main():
    root = tk.Tk()
    Application(root)
    root.mainloop()

if __name__ == "__main__":
    main()