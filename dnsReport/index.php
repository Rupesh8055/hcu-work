<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DNS Report Tool</title>
    <style>
        body { font-family: Arial; background: #f5f5f5; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; }
        form { margin-bottom: 30px; }
        input[type="text"] { width: 70%; padding: 10px; margin-right: 10px; }
        input[type="submit"] { padding: 10px 20px; }
        pre { background: #f0f0f0; padding: 20px; border-radius: 5px; overflow-x: auto; }
        .error { color: red; font-weight: bold; }
    </style>
</head>
<body>
<div class="container">
    <h1>DNS Report Tool</h1>
    <form method="POST" action="run_dns_report.php">
        <input type="text" name="domain" placeholder="Enter domain (e.g., example.com)" required />
        <input type="submit" value="Generate Report" />
    </form>

    <?php if (isset($_GET['output'])): ?>
        <h2>DNS Report for <?= htmlspecialchars($_GET['domain']) ?></h2>
        <pre><?= htmlspecialchars(file_get_contents($_GET['output'])) ?></pre>
        <p><a href="<?= $_GET['output'] ?>" download>Download Report</a></p>
    <?php elseif (isset($_GET['error'])): ?>
        <p class="error"><?= htmlspecialchars($_GET['error']) ?></p>
    <?php endif; ?>
</div>
</body>
</html>
