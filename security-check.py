import os  # pentru crearea de fisiere in pc
import sys  # pentru primirea de argumente din linia de comanda
import subprocess  # pentru rularea de comenzi de sistem
import ast  # abstract syntax trees
from typing import Set
import shutil  # pentru a sterge directoare


def clone_repo(url: str) -> str:
    # copiem in pc repo-ul
    try:
        repo_name = url.split("/")[-1].replace(".git", "")
        subprocess.run(["git", "clone", url], check=True)
        return repo_name
    except Exception as e:
        print(f"Error while cloning the repo: {e}")
        sys.exit()


def imported_libs(path: str) -> Set[str]:  # primeste path-ul de la repo
    # gasim module/pachete importate si le scriem in requirements.txt
    try:
        imported = set()
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".py"):  
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8") as f:
                        tree = ast.parse(f.read(), filename=file_path)
                    for node in ast.walk(tree):  # itereaza prin toate nodurile arborelui
                        if isinstance(node, ast.ImportFrom):  # nod de tip "from... import"
                            imported.update(alias.name for alias in node.names)
                        elif isinstance(node, ast.Import):  #nod de tip "import ..."
                            imported.update(alias.name for alias in node.names)
        with open("requirements.txt", "w") as req_file:
            for lib in imported:
                req_file.write(f"{lib}\n")
        return imported
    except Exception as e:
        print(f"Error while finding imported libraries: {e}")
        sys.exit()


def check_library_safety(path:str):
    # verifica librariile cu safety tool si afiseaza rezultatele
    try:
        if not os.path.exists("requirements.txt"):
            print("No requirements.txt file found")
            sys.exit()
        result = subprocess.run(
            ["safety", "check", "-r", "requirements.txt"], 
            capture_output=True,
            text=True,
        )
        return result.stdout
    except Exception as e:
        print(f"Error while checking safety: {e}")
        sys.exit()


def check_code_bandit(path: str):
    # analizeaza vulnerabilitati din cod cu Bandit
    try:
        result = subprocess.run(
            ["bandit", "-r", path,"-ll"],  
            #["bandit", path,"-lll"]
            # -l = low severity
            # -ll = medium severity
            # -lll = high severity
            capture_output=True, 
            text=True,
        )
        return result.stdout
    except Exception as e:
        print(f"Error while Bandit analysis: {e}")
        sys.exit()


def handle_remove_readonly(func, path, exc_info):
    # sterge fisiere care nu pot fi sterse simplu cu os.remove sau subprocces.run(["rm"])
    if not os.access(path, os.W_OK):
        os.chmod(path, 0o777)
        func(path)
    else:
        raise exc_info[1]


def main():
    if len(sys.argv) != 2:
        print("Numar de argumente necorespunzator")
        sys.exit()
    url_git = sys.argv[1]
    repo = clone_repo(url_git)
    print(f"Imported libraries/functions: {imported_libs(repo)}")
    print(f"Library vulnerabilities:\n{check_library_safety(repo)}")
    print(f"Code vulnerabilities:\n{check_code_bandit(repo)}")
    shutil.rmtree(repo, onerror=handle_remove_readonly)
main()
