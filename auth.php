<?php
session_start();

// PART 1: DATABASE SETUP
try {
    $pdo = new PDO(
        "mysql:host=127.0.0.1;charset=utf8mb4",
        "root",
        "",
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    $pdo->exec("CREATE DATABASE IF NOT EXISTS foundit");
    $pdo->exec("USE foundit");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(50) NOT NULL,
            last_name VARCHAR(50) NOT NULL,
            username VARCHAR(50) NOT NULL UNIQUE,
            email VARCHAR(100) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            verification_code VARCHAR(4) DEFAULT NULL,
            is_verified TINYINT(1) DEFAULT 0,
            is_admin TINYINT(1) DEFAULT 0
        )
    ");
} catch (PDOException $e) {
    die("Database connection failed. Check that XAMPP's database is running.");
}

function go($page) {
    header("Location: auth.php?page=" . $page);
    exit;
}

function h($value) {
    return htmlspecialchars((string)$value, ENT_QUOTES, "UTF-8");
}

function new_code($pdo, $email) {
    $code = str_pad(
        (string)random_int(0, 9999),
        4,
        "0",
        STR_PAD_LEFT
    );

    $stmt = $pdo->prepare(
        "UPDATE users SET verification_code = ? WHERE email = ?"
    );
    $stmt->execute([$code, $email]);

    // DEMO ONLY: display the code for testing.
    $_SESSION["demo_code"] = $code;
}

$page = $_GET["page"] ?? "login";
$allowed_pages = [
    "register", "verify", "login",
    "forgot", "change", "home", "logout"
];

if (!in_array($page, $allowed_pages, true)) {
    $page = "login";
}

$error = "";
$message = "";
$is_post = $_SERVER["REQUEST_METHOD"] === "POST";

// PART 2: REGISTRATION
if ($page === "register" && $is_post) {
    $first = trim($_POST["first_name"] ?? "");
    $last = trim($_POST["last_name"] ?? "");
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirm = $_POST["confirm_password"] ?? "";

    if (
        $first === "" || $last === "" ||
        $username === "" || $email === "" ||
        $password === "" || $confirm === ""
    ) {
        $error = "Please fill in all fields.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email address.";
    } elseif (strlen($password) < 8) {
        $error = "Password must be at least 8 characters.";
    } elseif ($password !== $confirm) {
        $error = "Passwords do not match.";
    } else {
        $stmt = $pdo->prepare(
            "SELECT id FROM users WHERE username = ? OR email = ?"
        );
        $stmt->execute([$username, $email]);

        if ($stmt->fetch()) {
            $error = "Username or email already exists.";
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $pdo->prepare("
                INSERT INTO users
                (first_name, last_name, username, email, password)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $first, $last, $username, $email, $hash
            ]);

            new_code($pdo, $email);
            $_SESSION["pending_email"] = $email;
            $_SESSION["purpose"] = "register";

            

            header("Location: signup-verification.php");
            exit;
        }
    }
}

// PART 3: VERIFY ACCOUNT OR PASSWORD RESET
if ($page === "verify") {
    if (!isset($_SESSION["pending_email"])) {
        go("login");
    }

    $email = $_SESSION["pending_email"];
    $purpose = $_SESSION["purpose"] ?? "register";

    if ($is_post && isset($_POST["resend"])) {
        new_code($pdo, $email);
        $message = "A new demo code was generated.";
    } elseif ($is_post) {
        $entered = trim($_POST["code"] ?? "");

        $stmt = $pdo->prepare(
            "SELECT verification_code FROM users WHERE email = ?"
        );
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (
            $user &&
            $user["verification_code"] !== null &&
            $user["verification_code"] === $entered
        ) {
            $stmt = $pdo->prepare(
                "UPDATE users SET verification_code = NULL WHERE email = ?"
            );
            $stmt->execute([$email]);

            unset(
                $_SESSION["demo_code"],
                $_SESSION["pending_email"],
                $_SESSION["purpose"]
            );

            if ($purpose === "register") {
                $stmt = $pdo->prepare(
                    "UPDATE users SET is_verified = 1 WHERE email = ?"
                );
                $stmt->execute([$email]);

                go("login&verified=1");
            } else {
                $_SESSION["reset_email"] = $email;
                go("change");
            }
        } else {
            $error = "Incorrect verification code.";
        }
    }
}

// PART 4: LOGIN
if ($page === "login" && $is_post) {
    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    $stmt = $pdo->prepare(
        "SELECT * FROM users WHERE username = ?"
    );
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user["password"])) {
        $error = "Wrong username or password.";
    } elseif (!$user["is_verified"]) {
        $error = "Please verify your account first.";
    } elseif (isset($_POST["admin"]) && !$user["is_admin"]) {
        $error = "This account is not an admin.";
    } else {
        session_regenerate_id(true);

        $_SESSION["user_id"] = $user["id"];
        $_SESSION["username"] = $user["username"];
        $_SESSION["is_admin"] = $user["is_admin"];

        go("home");
    }
}

// PART 5: FORGOT PASSWORD
if ($page === "forgot" && $is_post) {
    $email = trim($_POST["email"] ?? "");

    $stmt = $pdo->prepare(
        "SELECT id FROM users WHERE email = ?"
    );
    $stmt->execute([$email]);

    if (!$stmt->fetch()) {
        $error = "No account found with that email.";
    } else {
        new_code($pdo, $email);
        $_SESSION["pending_email"] = $email;
        $_SESSION["purpose"] = "reset";

        go("verify");
    }
}

// PART 6: CHANGE PASSWORD
if ($page === "change") {
    if (!isset($_SESSION["reset_email"])) {
        go("forgot");
    }

    if ($is_post) {
        $new = $_POST["new_password"] ?? "";
        $confirm = $_POST["confirm_password"] ?? "";

        if (strlen($new) < 6) {
            $error = "Password must be at least 6 characters.";
        } elseif ($new !== $confirm) {
            $error = "Passwords do not match.";
        } else {
            $hash = password_hash($new, PASSWORD_DEFAULT);

            $stmt = $pdo->prepare(
                "UPDATE users SET password = ?, verification_code = NULL
                 WHERE email = ?"
            );
            $stmt->execute([$hash, $_SESSION["reset_email"]]);

            unset($_SESSION["reset_email"]);
            go("login&reset=1");
        }
    }
}

// PART 7: PROTECT HOME PAGE
if ($page === "home" && !isset($_SESSION["user_id"])) {
    go("login");
}

// PART 8: LOGOUT
if ($page === "logout") {
    $_SESSION = [];
    session_destroy();
    go("login");
}

// PART 9: PAGE DESIGNS
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>FoundIT</title>
    <style>
        * { box-sizing: border-box; }

        body {
            margin: 0;
            padding: 24px;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: #f1f5f9;
            font-family: Arial, sans-serif;
            color: #1e293b;
        }

        .card {
            background: white;
            width: 100%;
            max-width: 440px;
            padding: 28px;
            border-radius: 14px;
            box-shadow: 0 8px 30px #00000012;
        }

        h1 { margin-top: 0; color: #2563eb; }
        p { line-height: 1.5; }

        input {
            width: 100%;
            padding: 12px;
            margin: 6px 0 14px;
            border: 1px solid #cbd5e1;
            border-radius: 7px;
        }

        button {
            width: 100%;
            padding: 12px;
            border: 0;
            border-radius: 7px;
            background: #2563eb;
            color: white;
            font-weight: bold;
            cursor: pointer;
        }

        button:hover { background: #1d4ed8; }
        a { color: #2563eb; }
        .error { color: #dc2626; }
        .message { color: #15803d; }
        .links { margin-top: 18px; }
        .links a { margin-right: 12px; }
        .check { margin: 0 0 16px; }
        .check input { width: auto; margin: 0 6px 0 0; }
    </style>
</head>
<body>
<div class="card">
<?php
switch ($page):

case "register":
?>
    <h1>Create Account</h1>
    <p>Register for FoundIT.</p>
    <?php if ($error !== ""): ?><p class="error"><?= h($error) ?></p><?php endif; ?>
    <form method="post">
        <label>First name</label>
        <input name="first_name" required>
        <label>Last name</label>
        <input name="last_name" required>
        <label>Username</label>
        <input name="username" required>
        <label>Email</label>
        <input type="email" name="email" required>
        <label>Password</label>
        <input type="password" name="password" required>
        <label>Confirm password</label>
        <input type="password" name="confirm_password" required>
        <button type="submit">Register</button>
    </form>
    <div class="links"><a href="auth.php?page=login">Back to login</a></div>
<?php
break;

case "verify":
?>
    <h1>Verify Account</h1>
    <p>Enter the four-digit demo code shown below.</p>
    <?php if ($error !== ""): ?><p class="error"><?= h($error) ?></p><?php endif; ?>
    <?php if ($message !== ""): ?><p class="message"><?= h($message) ?></p><?php endif; ?>
    <?php if (isset($_SESSION["demo_code"])): ?>
        <p class="message">Demo code: <strong><?= h($_SESSION["demo_code"]) ?></strong></p>
    <?php endif; ?>
    <form method="post">
        <label>Four-digit code</label>
        <input name="code" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" required>
        <button type="submit">Verify</button>
    </form>
    <form method="post">
        <button name="resend" value="1" formnovalidate>Generate new code</button>
    </form>
<?php
break;

case "forgot":
?>
    <h1>Forgot Password?</h1>
    <p>Enter the email linked to your account.</p>
    <?php if ($error !== ""): ?><p class="error"><?= h($error) ?></p><?php endif; ?>
    <form method="post">
        <label>Email</label>
        <input type="email" name="email" required>
        <button type="submit">Continue</button>
    </form>
    <div class="links"><a href="auth.php?page=login">Back to login</a></div>
<?php
break;

case "change":
?>
    <h1>Create New Password</h1>
    <?php if ($error !== ""): ?><p class="error"><?= h($error) ?></p><?php endif; ?>
    <form method="post">
        <label>New password</label>
        <input type="password" name="new_password" required>
        <label>Confirm new password</label>
        <input type="password" name="confirm_password" required>
        <button type="submit">Change Password</button>
    </form>
<?php
break;

case "home":
?>
    <h1>Welcome to FoundIT!</h1>
    <p>Hello, <?= h($_SESSION["username"]) ?>.</p>
    <?php if (!empty($_SESSION["is_admin"])): ?>
        <p>You are logged in as an administrator.</p>
    <?php endif; ?>
    <p>Your account is logged in successfully.</p>
    <a href="auth.php?page=logout">Log out</a>
<?php
break;

case "login":
default:
?>
    <h1>FoundIT</h1>
    <p>Log in to your account.</p>

    <?php if ($error !== ""): ?><p class="error"><?= h($error) ?></p><?php endif; ?>
    <?php if (isset($_GET["verified"])): ?><p class="message">Account verified! You can log in.</p><?php endif; ?>
    <?php if (isset($_GET["reset"])): ?><p class="message">Password changed successfully.</p><?php endif; ?>

    <form method="post">
        <label>Username</label>
        <input name="username" required>
        <label>Password</label>
        <input type="password" name="password" required>
        <div class="check">
            <label><input type="checkbox" name="admin" value="1"> Admin login</label>
        </div>
        <button type="submit">Log In</button>
    </form>

    <div class="links">
        <a href="auth.php?page=register">Register</a>
        <a href="auth.php?page=forgot">Forgot password?</a>
    </div>
<?php
endswitch;
?>
</div>
</body>
</html>
