from app.extractors.smtp_extractor import extract_smtp

FAKE_SENDGRID = "SG." + ("a" * 22) + "." + ("b" * 43)


def test_jconfig_smtp_extraction():
    text = f"""
    <?php class JConfig {{
        public $smtphost = 'smtp.sendgrid.net';
        public $smtpport = '587';
        public $smtpuser = 'apikey';
        public $smtppass = '{FAKE_SENDGRID}';
    }}
    """
    smtp = extract_smtp(text, source_url="https://t/configuration.php", redact_values=False)
    full = next(s for s in smtp if s["value"].get("pass"))
    assert full["value"]["host"] == "smtp.sendgrid.net"
    assert full["value"]["pass"] == FAKE_SENDGRID


def test_wp_define_smtp_extraction():
    text = f"""
    define('SMTP_HOST', 'smtp.sendgrid.net');
    define('SMTP_PORT', '587');
    define('SMTP_USER', 'apikey');
    define('SMTP_PASS', '{FAKE_SENDGRID}');
    """
    smtp = extract_smtp(text, source_url="https://t/wp-config.php", redact_values=False)
    full = next(s for s in smtp if s["value"].get("pass"))
    assert full["value"]["host"] == "smtp.sendgrid.net"
    assert full["value"]["pass"] == FAKE_SENDGRID
