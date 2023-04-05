import tkinter as tk
from tkinter import ttk

# import crypify

def search_button_event(name:str, output_var, root):
    result = get_proposals(name)
    if len(result) > 0:
        result_txt = ''
        for entry in result:
            result_txt += f"'{entry}', "
        result_txt = result_txt[:-2] + "."
        output = f"Persons who watched '{name}' also watched {result_txt}"
    else:
        output = f"There are no proposals for the film/series '{name}'.\nMake sure the Film/Series exist and is written right."
    output_var.set(f"Output:\n{output}")
    update_size(root)

def update_size(root):
    root.minsize(0, 0)
    width = root.winfo_width()
    height = root.winfo_height()
    root.geometry('')
    root.update()
    root.minsize(root.winfo_width(), root.winfo_height())
    root.geometry(f"{width}x{height}")

root = tk.Tk()
root.title("Watch Proposal")
root.geometry("600x400")
#root.minsize(400, 200)

main_window = ttk.Frame(root)
main_window.pack(expand=True, fill='both')

input_label = ttk.Label(main_window, text="User-Input:")
input_label.grid(row=1, column=1, sticky="nswe", pady=10, padx=20)

user_input = tk.StringVar()
input_entry = ttk.Entry(main_window, textvariable=user_input)
input_entry.grid(row=1, column=2, sticky="we", pady=10, padx=20)

output_var = tk.StringVar()
output_var.set("Output:")
output_label = ttk.Label(main_window, textvariable=output_var, borderwidth=2)
output_label.grid(row=3, rowspan=2, column=1, columnspan=2, sticky="nswe", pady=10, padx=20)

search_button = ttk.Button(main_window, text="search", command=lambda: search_button_event(user_input.get(), output_var, root), takefocus=0)
search_button.grid(row=2, column=1, columnspan=2, sticky="nswe", ipady=10, padx=20)

# set weights for resizable
for i in range(6):
    main_window.grid_rowconfigure(i, weight=1)
for i in range(4):
    main_window.grid_columnconfigure(i, weight=1)

update_size(root)
root.geometry("600x400")
root.mainloop()