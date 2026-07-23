"""
=============================================================
  PASSWORD SECURITY AUDITOR
  University of The Gambia – Security Script Programming
  Group Project
=============================================================
"""

from fileinput import filename
import re
import random
import string
import hashlib
import os
import datetime
import json
import secrets as secret

from rich.console import Console
from rich.table import Table
from rich.progress import track, Progress, BarColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt
from rich import box

console = Console()

# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
LOG_FILE = "password_log.txt"
HISTORY_FILE = "password_history.json"
COMMON_PASSWORDS_FILE = "common_passwords.txt"

COMMON_PASSWORDS_DEFAULT = [
    # Initial 20
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "letmein", "monkey", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow",
    "superman", "michael", "football", "iloveyou", "admin",

    # Number Sequences & Patterns
    "12345", "12345678", "1234", "1111", "000000", 
    "0000", "123123", "666666", "777777", "888888", 
    "999999", "1234567", "1q2w3e", "!@#$%", "1234567890",

    # Keyboard Walks
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsx", "wsxedc", 
    "edcrfv", "asdf", "zxcv", "qwerty123", "qweasd",

    # Default/System Terms
    "password123", "pass123", "admin123", "root", "user", 
    "guest", "login", "test", "test123", "secret", 
    "secure", "myspace", "internet", "computer", "system", 
    "network", "server", "access", "default", "system123",

    # Common Names
    "fatou", "lamin", "modou", "isatou", "ebrima", 
    "mariama", "amadou", "aminata", "ousman", "binta", 
    "musa", "jainaba", "ibrahim", "nyima", "demba", 
    "yaya", "muhammad", "jallow", "alieu", "omar"

    # Pop Culture & Media
    "batman", "anime", "spiderman", "starwars", "pokemon", 
    "naruto", "matrix", "gandalf", "frodo", "harrypotter", 
    "hogwarts", "snoopy", "hello", "goodbye", "always", 
    "forever", "together", "family", "friends", "summer",

    # Dates & Seasons
    "spring", "autumn", "winter", "monday", "tuesday", 
    "friday", "sunday", "january", "october", "november", 
    "december", "2024", "2025", "2026", "2000",

    # Terms of Endearment & Slang
    "poop", "boobies", "sex", "love", "baby", 
    "angel", "sweetheart", "darling", "honey", "cutie", 
    "beautiful", "gorgeous", "handsome", "sexy", "crazy",

    # Animals
    "kitty", "puppy", "dog", "cat", "bird", 
    "fish", "tiger", "lion", "bear", "wolf",
    "eagle", "hawk", "snake", "spider", "butterfly",

    # Fantasy & Concepts
    "ninja", "samurai", "pirate", "knight", "warrior", 
    "wizard", "magic", "power", "strength", "courage", 
    "honor", "glory", "victory", "champion", "winner", 

    # Sports & Global Clubs
    "loser", "baseball", "basketball", "soccer", "hockey", 
    "tennis", "golf", "rugby", "cricket", "volleyball", 
    "swimming", "running", "jumping", "barcelona", "manunited", 
    "psg", "chelsea", "arsenal", "liverpool", "madrid",

    # Colors & Elements
    "bayern", "red", "blue", "green", "yellow", 
    "orange", "purple", "black", "white", "pink", 
    "brown", "silver", "gold", "platinum", "diamond", 
    "ruby", "emerald", "sapphire", "crystal", "pearl"
]

# ─────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────

def display_banner():
    """Display the application banner."""
    console.print(
        Panel.fit(
            "[bold cyan]🔐 PASSWORD SECURITY AUDITOR[/]\n"
            "[underline]University of The Gambia – Security Script Programming[/]\n"
            "[italic]Group Project[/italic]",
            border_style="bright_blue"
        )
    )
    console.print()


def log_event(message):
    """Write an event log entry to the log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}\n"
    try:
        with open(LOG_FILE, "a") as log:
            log.write(entry)
    except IOError as e:
        console.print(f"  [yellow][Warning] Could not write to log file: {e}[/]")


def load_common_passwords():
    """
    Load common passwords from file.
    If file does not exist, create it with default values.
    """
    if not os.path.exists(COMMON_PASSWORDS_FILE):
        try:
            with open(COMMON_PASSWORDS_FILE, "w") as f:
                for pw in COMMON_PASSWORDS_DEFAULT:
                    f.write(pw + "\n")
        except IOError as e:
            console.print(f"  [yellow][Warning] Could not create common passwords file: {e}[/]")
            return set(COMMON_PASSWORDS_DEFAULT)

    try:
        with open(COMMON_PASSWORDS_FILE, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except IOError as e:
        console.print(f"  [yellow][Warning] Could not read common passwords file: {e}[/]")
        return set(COMMON_PASSWORDS_DEFAULT)


def hash_password(password):
    """Return the SHA-256 hash of a password (for safe logging)."""
    return hashlib.sha256(password.encode()).hexdigest()


def save_to_history(password, strength_label):
    """Save a generated password hash and strength to history JSON file."""
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except (IOError, json.JSONDecodeError):
            history = []

    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hash": hash_password(password),
        "strength": strength_label,
        "length": len(password)
    }
    history.append(entry)

    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=4)
    except IOError as e:
        console.print(f"  [yellow][Warning] Could not save to history: {e}[/]")


def view_history():
    """Display password generation history from the JSON file."""
    if not os.path.exists(HISTORY_FILE):
        console.print("\n[yellow]No history found yet.[/]\n")
        return

    try:
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)

        if not history:
            console.print("\n[yellow]History is empty.[/]\n")
            return

        table = Table(title="Password Generation History", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Date & Time", style="cyan", width=22)
        table.add_column("Strength", width=12)
        table.add_column("Length", justify="center", width=8)
        table.add_column("Hash (truncated)", style="green")

        color_map = {"Very Weak":"red", "Weak":"yellow", "Moderate":"magenta", "Strong":"blue", "Very Strong":"green"}
        for i, entry in enumerate(history, 1):
            short_hash = entry["hash"][:16] + "..."
            strength = entry["strength"]
            colored_strength = f"[{color_map.get(strength, 'white')}]{strength}[/]"
            table.add_row(str(i), entry["timestamp"], colored_strength, str(entry["length"]), short_hash)

        console.print(table)
        console.print(f"  Total records: {len(history)}\n")

    except (IOError, json.JSONDecodeError) as e:
        console.print(f"[red]Error reading history: {e}[/]")


# ─────────────────────────────────────────────
#  CORE FUNCTIONS
# ─────────────────────────────────────────────

def check_password_strength(password, common_passwords):
    """
    Analyse a password and return a strength report.

    Scoring:
      - Length >= 8        → +1
      - Length >= 12       → +1
      - Uppercase letter   → +1
      - Lowercase letter   → +1
      - Digit              → +1
      - Special character  → +1
      - Not common         → +1

    Returns: (score, label, feedback_list)
    """
    feedback = []
    score = 0

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("✗ Use at least 8 characters.")

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("  (Tip: 12+ characters makes it much stronger.)")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("✗ Add at least one uppercase letter (A–Z).")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("✗ Add at least one lowercase letter (a–z).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("✗ Add at least one digit (0–9).")

    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        score += 1
    else:
        feedback.append("✗ Add at least one special character (!@#$%^&* …).")

    if password.lower() in common_passwords:
        feedback.append("[bold]✗ This is a commonly used password — avoid it!")
        score = max(0, score - 2)
    else:
        score += 1

    if score <= 2:
        label = "Very Weak"
    elif score == 3:
        label = "Weak"
    elif score == 4:
        label = "Moderate"
    elif score == 5:
        label = "Strong"
    else:
        label = "Very Strong"

    return score, label, feedback


def display_strength_result(password, score, label, feedback):
    """Print the strength analysis result."""
    max_score = 7

    # Progress bar for strength
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=20),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Strength", total=max_score)
        progress.update(task, completed=score)

    color_map = {"Very Weak":"red", "Weak":"yellow", "Moderate":"magenta", "Strong":"blue", "Very Strong":"green"}
    icon = {"Very Weak":"🔴", "Weak":"🟠", "Moderate":"🟡", "Strong":"🟢", "Very Strong":"✅"}.get(label, "⚪")

    console.print(f"  Password Length : {len(password)}")
    console.print(f"  Score           : {score} / {max_score}")
    console.print(f"  Strength Level  : {icon}  [{color_map.get(label, 'white')}]{label}[/]")

    if feedback:
        console.print("\n  [bold]Suggestions:[/]")
        for tip in feedback:
            console.print(f"    {tip}")
    else:
        console.print("\n  [green]✅ Your password meets all strength criteria![/]")

    console.rule()


def generate_password(length, use_upper, use_lower, use_digits, use_special):
    """
    Generate a random password based on user preferences.

    Parameters:
        length      (int)  : desired password length
        use_upper   (bool) : include uppercase letters
        use_lower   (bool) : include lowercase letters
        use_digits  (bool) : include digits
        use_special (bool) : include special characters

    Returns: generated password string, or None if no character set selected.
    """
    character_pool = ""
    guaranteed = []

    if use_upper:
        character_pool += string.ascii_uppercase
        guaranteed.append(secret.choice(string.ascii_uppercase))

    if use_lower:
        character_pool += string.ascii_lowercase
        guaranteed.append(secret.choice(string.ascii_lowercase))

    if use_digits:
        character_pool += string.digits
        guaranteed.append(secret.choice(string.digits))

    if use_special:
        specials = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        character_pool += specials
        guaranteed.append(secret.choice(specials))

    if not character_pool:
        return None

    # Fill remaining length with random characters from pool
    remaining = length - len(guaranteed)
    if remaining < 0:
        remaining = 0

    random_chars = [secret.choice(character_pool) for _ in range(remaining)]
    password_list = guaranteed + random_chars

    # Shuffle so guaranteed chars aren't always at the start
    random.shuffle(password_list)

    return "".join(password_list)


# def get_yes_no(prompt):
#     """Ask a yes/no question and return True for yes, False for no."""
#     while True:
#         answer = input(prompt).strip().lower()
#         if answer in ("y", "yes"):
#             return True
#         elif answer in ("n", "no"):
#             return False
#         else:
#             print("  Please enter 'y' or 'n'.")


# def get_integer(prompt, min_val, max_val):
#     """Prompt user for an integer within [min_val, max_val]."""
#     while True:
#         try:
#             value = int(input(prompt).strip())
#             if min_val <= value <= max_val:
#                 return value
#             else:
#                 print(f"  Please enter a number between {min_val} and {max_val}.")
#         except ValueError:
#             print("  Invalid input. Please enter a whole number.")



# ─────────────────────────────────────────────
#  MENU HANDLERS
# ─────────────────────────────────────────────

def menu_check_password(common_passwords):
    """Handle the Check Password Strength flow."""
    console.rule("[bold cyan]CHECK PASSWORD STRENGTH[/]")
    password = input("  Enter the password to check: ")

    if not password:
        console.print("  [red][Error] No password entered.[/]\n")
        log_event("CHECK: Empty password entered.")
        return

    score, label, feedback = check_password_strength(password, common_passwords)
    display_strength_result(password, score, label, feedback)

    log_event(f"CHECK: length={len(password)}, strength={label}, score={score}/7")


def menu_generate_password(common_passwords):
    """Handle the Generate Password flow."""
    console.rule("[bold cyan]GENERATE PASSWORD[/]")

    length = IntPrompt.ask("Desired password length (8–128)", default="default: 12", choices=[str(i) for i in range(8, 129)], show_choices=False)

    console.print()
    use_upper   = Confirm.ask("Include uppercase letters?")
    use_lower   = Confirm.ask("Include lowercase letters?")
    use_digits  = Confirm.ask("Include digits?")
    use_special = Confirm.ask("Include special characters?")

    if not any([use_upper, use_lower, use_digits, use_special]):
        console.print("\n[red][Error] You must select at least one character type.[/]\n")
        return

    password = generate_password(length, use_upper, use_lower, use_digits, use_special)

    if password is None:
        console.print("\n[red][Error] Could not generate password with the given options.[/]\n")
        return

    console.print(f"\n  ✅ Generated Password: [green]{password}[/]")

    # Automatically check strength of generated password
    score, label, feedback = check_password_strength(password, common_passwords)
    display_strength_result(password, score, label, feedback)

    save_to_history(password, label)
    log_event(f"GENERATE: length={len(password)}, strength={label}")


def menu_analyze_password_file(common_passwords):
    """Handle the Analyze Password File flow."""
    filename = input("\nEnter the password file name: ").strip()

    try:
        with open(filename, "r") as file:
            passwords = [p.strip() for p in file.readlines() if p.strip()]
    except FileNotFoundError:
        console.print("\n[red][Error] File not found.[/]\n")
        log_event(f"AUDIT ERROR: File '{filename}' not found.")        
        return

    if not passwords:
        console.print("\n[yellow][Warning] File is empty.[/]\n")
        return

    results = []

     # very_weak = 0
    # weak = 0
    # moderate = 0
    # strong = 0
    # very_strong = 0

    for password in track(passwords, description="[cyan]Auditing passwords..."):
        score, label, _ = check_password_strength(password, common_passwords)
        results.append((password, score, label))

    # Build Rich table
    table = Table(title="Password Audit Results", box=box.ROUNDED)
    table.add_column("Password", style="bold", width=20)
    table.add_column("Strength", width=12)
    table.add_column("Score", justify="center", width=6)

    color_map = {"Very Weak":"red", "Weak":"yellow", "Moderate":"magenta", "Strong":"blue", "Very Strong":"green"}
    for pwd, score, label in results:
        colored_label = f"[{color_map.get(label, 'white')}]{label}[/]"
        table.add_row(pwd[:20], colored_label, f"{score}/7")

    console.print(table)

    # Summary 
    total = len(results)
    counts = {}
    for _, _, label in results:
        counts[label] = counts.get(label, 0) + 1

    console.print("\n[bold]Summary:[/]")
    for label in ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]:
        cnt = counts.get(label, 0)
        if cnt:
            color = color_map.get(label, "white")
            console.print(f"  [{color}]{label}:[/] {cnt}")

    # Save report
    with open("audit_report.txt", "w") as report:
        report.write("PASSWORD AUDIT REPORT\n")
        report.write("=" * 40 + "\n\n")
        for pwd, score, label in results:
            report.write(f"{pwd} - {label} ({score}/7)\n")
        report.write("\nSummary:\n")
        for label in ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]:
            cnt = counts.get(label, 0)
            report.write(f"  {label}: {cnt}\n")

    console.print("\n  [green]✅ Audit report saved to 'audit_report.txt'[/]\n")


def menu_view_log():
    """Display the raw event log file."""
    console.rule("[bold cyan]EVENT LOG[/]")
    if not os.path.exists(LOG_FILE):
        console.print("  No log entries yet.\n")
        return

    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()

        if not lines:
            console.print("  Log file is empty.\n")
            return

        recent = lines[-20:]
        console.print(f"  (Showing last {len(recent)} of {len(lines)} entries)\n")
        for line in recent:
            console.print(f"  {line}", end="")
        console.print()

    except IOError as e:
        console.print(f"  [red][Error] Could not read log: {e}[/]\n")


# ─────────────────────────────────────────────
#  MAIN PROGRAM
# ─────────────────────────────────────────────

def main():
    """Entry point – main menu loop."""
    display_banner()
    common_passwords = load_common_passwords()
    log_event("SESSION STARTED")

    while True:
        console.print("  ─────────────────────────────────")
        console.print("             [bold]MAIN MENU[/]")
        console.print("  ─────────────────────────────────")
        console.print("  [1] Check Password Strength")
        console.print("  [2] Generate a Secure Password")
        console.print("  [3] Analyze Password File")
        console.print("  [4] View Generation History")
        console.print("  [5] View Event Log")
        console.print("  [6] Exit")
        console.print("  ─────────────────────────────────")
        console.print()

        choice = input("  Select an option (1–6): ").strip()

        if choice == "1":
            menu_check_password(common_passwords)
        elif choice == "2":
            menu_generate_password(common_passwords)
        elif choice == "3":
            menu_analyze_password_file(common_passwords)
        elif choice == "4":
            view_history()
        elif choice == "5":
            menu_view_log()
        elif choice == "6":
            log_event("SESSION ENDED")
            console.print("\n[green]Goodbye! Stay secure. 🔐[/]\n")
            break
        else:
            console.print("\n[red][Error] Invalid option. Please choose 1–6.[/]\n")

if __name__ == "__main__":
    main()