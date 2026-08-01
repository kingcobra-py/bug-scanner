from app.extractors.joomla_api_extractor import extract_joomla_apis


def test_joomla_api_paths_and_routes():
    body = """
    <script>
      const endpoint = '/api/index.php/v1/content/articles';
      fetch('https://cms.nightwatch.local/api/index.php/v1/users');
      const legacy = '/index.php?option=com_ajax&task=run';
    </script>
    {"routes":["/api/index.php/v1/content","/v1/banners"],"namespaces":["v1"]}
    """
    out = extract_joomla_apis(body, source_url="https://cms.nightwatch.local/")
    values = {item["value"] for item in out["apis"]}
    assert any("/api/index.php/v1/content/articles" in v for v in values)
    assert any("/api/index.php/v1/users" in v for v in values)
    assert any("option=com_ajax" in v for v in values)
    assert all(item.get("extractor") == "joomla" for item in out["apis"])


def test_jconfig_secret_and_api_fields():
    body = """
    <?php
    class JConfig {
      public $secret = 'a1b2c3d4e5f6g7h8i9j0';
      public $password = 'SuperSecretPass1';
      public $live_site = 'https://cms.nightwatch.local';
      public $smtphost = 'smtp.nightwatch.local';
      public $api_key = 'joomla_api_key_value_123456';
    }
    """
    out = extract_joomla_apis(body, source_url="https://cms.nightwatch.local/configuration.php", redact_values=True)
    kinds = {item["kind"] for item in out["secrets"]}
    assert "jconfig_secret" in kinds
    assert "jconfig_password" in kinds
    assert "jconfig_api_key" in kinds
    api_values = {item["value"] for item in out["apis"]}
    assert "https://cms.nightwatch.local" in api_values
    assert "smtp.nightwatch.local" in api_values
