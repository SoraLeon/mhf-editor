import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import struct
import os
import webbrowser

def read_pointer_table(data):
    if data[:4] == b'\x00\x00\x00\x00':
        return read_variant2(data), 2  # Retorna tipo 2
    else:
        return read_variant1(data), 1  # Retorna tipo 1

def read_variant1(data):
    pointers = []
    i = 0
    while i + 4 <= len(data):
        ptr = struct.unpack_from('<I', data, i)[0]
        if ptr == 0xFFFFFFFF:
            break
        pointers.append(ptr)
        i += 4
    return pointers

def read_variant2(data):
    pointers = []
    first_ptr = struct.unpack_from('<I', data, 0x4)[0]
    end_table = first_ptr - 1
    i = 0x4
    while i <= end_table:
        ptr = struct.unpack_from('<I', data, i)[0]
        pointers.append(ptr)
        i += 16  # pula 16 bytes entre os ponteiros (4 bytes ponteiro + 12 bytes padding)
    return pointers

def extract_texts(data, pointers):
    texts = []
    for i, ptr in enumerate(pointers):
        start = ptr
        end = pointers[i + 1] if i + 1 < len(pointers) else len(data)
        segment = data[start:end]
        ascii_text = segment.split(b'\x00')[0].decode('ascii', errors='replace')
        length = len(ascii_text)  # tamanho original do texto em chars
        texts.append([ptr, ascii_text, ascii_text, length])  # [offset, ascii original, editado, tamanho original]
    return texts

def encode_custom(text):
    result = bytearray()
    for c in text:
        if c in 'áàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ':
            result += c.encode('utf-8')  # acentos = 2 bytes utf-8
        else:
            result += c.encode('ascii', errors='replace')  # ascii = 1 byte
    result += b'\x00'  # terminador
    return result

def count_custom_length(text):
    length = 0
    for c in text:
        if c in 'áàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ':
            length += 2
        else:
            length += 1
    return length

class PointerEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Text Editor Monster Hunter Freedom - Desenvolvido por Sora Leon")
        self.geometry("1400x700")
        self.iconbitmap("icon.ico")
        self.file_data = None
        self.pointers = []
        self.texts = []
        self.variant_type = 1

        self.search_results = []
        self.current_search_index = -1

        self.tree = ttk.Treeview(self, columns=("Offset", "Original", "Editado"), show="headings", height=30)
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=400 if col != "Offset" else 80)
        self.tree.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        self.editor_frame = tk.Frame(self)
        self.editor_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(self.editor_frame, text="Texto Original:").pack(anchor="w")
        self.original_text = tk.Text(self.editor_frame, height=8, width=80, state="disabled", bg="#f0f0f0")
        self.original_text.pack(fill=tk.X)

        tk.Label(self.editor_frame, text="Texto Editável:").pack(anchor="w", pady=(10, 0))
        self.editable_text = tk.Text(self.editor_frame, height=8, width=80)
        self.editable_text.pack(fill=tk.X)
        self.editable_text.bind("<KeyRelease>", self.check_space)

        self.space_label = tk.Label(self.editor_frame, text="Espaço disponível: N/A")
        self.space_label.pack(anchor="w", pady=(5, 10))

        ttk.Button(self.editor_frame, text="Aplicar Edição", command=self.apply_edit).pack(pady=10)

        search_frame = tk.Frame(self.editor_frame)
        search_frame.pack(pady=10)

        tk.Label(search_frame, text="Procurar:").grid(row=0, column=0, sticky="e")
        self.find_entry = tk.Entry(search_frame, width=30)
        self.find_entry.grid(row=0, column=1, padx=5)

        tk.Label(search_frame, text="Substituir por:").grid(row=1, column=0, sticky="e")
        self.replace_entry = tk.Entry(search_frame, width=30)
        self.replace_entry.grid(row=1, column=1, padx=5)

        ttk.Button(search_frame, text="Procurar Próximo", command=self.find_next).grid(row=0, column=2, padx=5)
        ttk.Button(search_frame, text="Substituir", command=self.replace_text).grid(row=1, column=2, padx=5)

        self.replace_all_var = tk.BooleanVar()
        ttk.Checkbutton(search_frame, text="Substituir em todos", variable=self.replace_all_var).grid(row=2, column=1, sticky="w", pady=5)

        btn_frame = tk.Frame(self.editor_frame)
        btn_frame.pack(fill=tk.X, pady=20)

        ttk.Button(btn_frame, text="Abrir BIN", command=self.open_file).pack(side=tk.LEFT, padx=10, expand=True)
        ttk.Button(btn_frame, text="Salvar BIN", command=self.save_file).pack(side=tk.LEFT, padx=10, expand=True)
        ttk.Button(btn_frame, text="Sobre Mim", command=self.show_about).pack(side=tk.LEFT, padx=10, expand=True)

        self.current_selected = None

    def show_about(self):
        win = tk.Toplevel(self)
        win.title("Sobre Mim")
        win.geometry("400x180")
        win.resizable(False, False)
        text = ("Desenvolvido Por Sora Leon - Versão 1.1.0\nFerramenta feita para editar os textos de Monster Hunter Freedom - PSP\n")
        tk.Label(win, text=text, justify="left").pack(pady=(10,5), padx=10, anchor="w")
        link1 = tk.Label(win, text="github.com/SoraLeon", fg="blue", cursor="hand2", font=("Arial", 10, "underline"))
        link1.pack(anchor="w", padx=10)
        link1.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/SoraLeon"))
        link2 = tk.Label(win, text="https://youtube/@SoraLeon", fg="blue", cursor="hand2", font=("Arial", 10, "underline"))
        link2.pack(anchor="w", padx=10, pady=(0,10))
        link2.bind("<Button-1>", lambda e: webbrowser.open_new("https://youtube.com/@SoraLeon"))

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
        if not path:
            return
        with open(path, "rb") as f:
            self.file_data = bytearray(f.read())
        result = read_pointer_table(self.file_data)
        self.pointers, self.variant_type = result
        self.texts = extract_texts(self.file_data, self.pointers)
        for i in range(len(self.texts)):
            self.texts[i][2] = self.texts[i][1]
        self.populate_tree()
        self.current_selected = None
        self.original_text.config(state="normal")
        self.original_text.delete("1.0", tk.END)
        self.original_text.config(state="disabled")
        self.editable_text.delete("1.0", tk.END)
        self.space_label.config(text="Espaço disponível: 0 chars", fg="green")
        self.search_results = []
        self.current_search_index = -1

    def populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        for i, (ptr, ascii_txt, edited_txt, _) in enumerate(self.texts):
            self.tree.insert("", "end", iid=i, values=(f"0x{ptr:X}", ascii_txt.split('\n')[0], edited_txt.split('\n')[0]))

    def on_select(self, event):
        if not self.tree.selection():
            return
        self.current_selected = int(self.tree.selection()[0])
        ptr, ascii_txt, edited_txt, _ = self.texts[self.current_selected]
        self.original_text.config(state="normal")
        self.original_text.delete("1.0", tk.END)
        self.original_text.insert("1.0", ascii_txt)
        self.original_text.config(state="disabled")
        self.editable_text.delete("1.0", tk.END)
        self.editable_text.insert("1.0", edited_txt)
        self.check_space()

    def check_space(self, event=None):
        if self.current_selected is None:
            self.space_label.config(text="Espaço disponível: N/A")
            return
        new_text = self.editable_text.get("1.0", tk.END).rstrip('\n').replace('\n', '\x0A')
        used = count_custom_length(new_text)
        space = self.calculate_space_for_text(self.current_selected)
        restante = space - used
        if restante < 0:
            self.space_label.config(text=f"Texto maior que o espaço! Excede em {-restante} chars", fg="red")
        else:
            self.space_label.config(text=f"Espaço restante após edição: {restante} chars", fg="green")

    def calculate_space_for_text_variant1(self, index):
        starts = self.pointers
        ends = self.pointers[1:] + [len(self.file_data)]
        original_lengths = [ends[i] - starts[i] for i in range(len(starts))]
        edited_texts = [item[2] for item in self.texts]

        original_space = [length - 1 for length in original_lengths]

        space_freed = 0
        for i in range(index):
            diff = original_space[i] - count_custom_length(edited_texts[i])
            if diff > 0:
                space_freed += diff

        available_space = original_space[index] + space_freed
        return max(0, available_space)

    def calculate_space_for_text_variant2(self, index):
        original_length = self.texts[index][3]  # tamanho original em chars (conta chars, não bytes)
        edited_texts = [item[2] for item in self.texts]

        # Calcula o espaço "liberado" acumulado das edições anteriores
        space_freed = 0
        for i in range(index):
            orig_len = self.texts[i][3]
            edited_len = count_custom_length(edited_texts[i])
            diff = orig_len - edited_len
            if diff > 0:
                space_freed += diff

        available_space = original_length + space_freed
        return max(0, available_space)


    def calculate_space_for_text(self, index):
        if self.variant_type == 1:
            return self.calculate_space_for_text_variant1(index)
        else:
            return self.calculate_space_for_text_variant2(index)

    def apply_edit(self):
        if self.current_selected is None:
            messagebox.showwarning("Aviso", "Selecione um texto para editar.")
            return
        new_text = self.editable_text.get("1.0", tk.END).rstrip('\n').replace('\n', '\x0A')
        space = self.calculate_space_for_text(self.current_selected)
        if count_custom_length(new_text) > space:
            messagebox.showerror("Erro", f"Texto maior que o espaço disponível ({space} chars).")
            return
        ptr, ascii_txt, _, _ = self.texts[self.current_selected]
        self.texts[self.current_selected][2] = new_text
        primeira_linha_edit = new_text.split('\x0A')[0]
        values = list(self.tree.item(self.current_selected, "values"))
        values[2] = primeira_linha_edit
        self.tree.item(self.current_selected, values=values)
        self.check_space()
        messagebox.showinfo("Sucesso", "Edição aplicada. Salve o arquivo para confirmar.")

    def save_file(self):
        if not self.file_data:
            messagebox.showwarning("Aviso", "Nenhum arquivo aberto.")
            return
        edited_texts = [item[2] for item in self.texts]

        if self.variant_type == 1:
            temp_data = bytearray()
            temp_pointers = []
            cursor = 0

            for txt in edited_texts:
                encoded = encode_custom(txt)
                temp_pointers.append(cursor)
                temp_data += encoded
                cursor += len(encoded)

            new_data = bytearray()
            for ptr in temp_pointers:
                new_data += struct.pack("<I", ptr + (len(temp_pointers) + 1) * 4)
            new_data += struct.pack("<I", 0xFFFFFFFF)
            new_data += temp_data

        else:
            new_data = bytearray()
            new_data += self.file_data[:0x20]

            for i, txt in enumerate(edited_texts):
                encoded = encode_custom(txt)
                offset = len(new_data)
                struct.pack_into("<I", new_data, 0x4 + i * 16, offset)
                new_data += encoded

            original_text_end = self.pointers[-1]
            last_text_len = len(encode_custom(edited_texts[-1]))
            original_after_texts_start = original_text_end + last_text_len

            if original_after_texts_start < len(self.file_data):
                new_data += self.file_data[original_after_texts_start:]

        save_path = filedialog.asksaveasfilename(defaultextension=".bin")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(new_data)
            messagebox.showinfo("Sucesso", "Arquivo salvo com sucesso!")

    def find_next(self):
        keyword = self.find_entry.get().strip().lower()
        if not keyword:
            return
        if not self.search_results or (self.texts[self.search_results[0]][2].lower().find(keyword) == -1 and self.texts[self.search_results[-1]][2].lower().find(keyword) == -1):
            self.search_results = [i for i, item in enumerate(self.texts) if keyword in item[2].lower()]
            self.current_search_index = -1
        if not self.search_results:
            messagebox.showinfo("Busca", f"'{keyword}' não encontrado.")
            return
        self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
        idx = self.search_results[self.current_search_index]
        self.tree.selection_set(idx)
        self.tree.see(idx)
        self.tree.focus(idx)
        self.current_selected = idx
        self.on_select(None)

    def replace_text(self):
        target = self.find_entry.get().strip()
        replacement = self.replace_entry.get().strip()
        if not target:
            return
        if self.replace_all_var.get():
            count = 0
            for i in range(len(self.texts)):
                old_text = self.texts[i][2]
                new_text = old_text.replace(target, replacement)
                if new_text != old_text:
                    self.texts[i][2] = new_text
                    values = list(self.tree.item(i, "values"))
                    values[2] = new_text.split('\x0A')[0]
                    self.tree.item(i, values=values)
                    count += 1
            messagebox.showinfo("Substituição", f"Substituição concluída em {count} itens.")
        else:
            if self.current_selected is None:
                messagebox.showwarning("Aviso", "Selecione um texto para substituir.")
                return
            old_text = self.texts[self.current_selected][2]
            new_text = old_text.replace(target, replacement)
            if new_text == old_text:
                messagebox.showinfo("Substituição", "Texto para substituir não encontrado.")
                return
            self.texts[self.current_selected][2] = new_text
            values = list(self.tree.item(self.current_selected, "values"))
            values[2] = new_text.split('\x0A')[0]
            self.tree.item(self.current_selected, values=values)
            self.editable_text.delete("1.0", tk.END)
            self.editable_text.insert("1.0", new_text)
            self.check_space()
            messagebox.showinfo("Substituição", "Substituição realizada.")

if __name__ == "__main__":
    PointerEditorApp().mainloop()
