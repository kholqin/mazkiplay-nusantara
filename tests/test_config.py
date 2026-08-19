from app.config import ScannerConfig, load_config


def test_default_config():
    config = ScannerConfig()

    assert config.timeout > 0
    assert config.connect_timeout > 0
    assert config.read_timeout > 0
    assert config.max_redirects >= 0
    assert config.max_pages >= 1
    assert config.max_sitemap_urls >= 1
    assert config.concurrency >= 1
    assert config.request_delay >= 0

    assert config.enable_headers is True
    assert config.enable_cookies is True
    assert config.enable_cors is True
    assert config.enable_csp is True
    assert config.enable_disclosure is True
    assert config.enable_redirects is True
    assert config.enable_robots is True
    assert config.enable_sitemap is True
    assert config.enable_crawler is True


def test_load_config():
    config = load_config()

    assert isinstance(config, ScannerConfig)
    assert config.max_pages >= 1
    assert config.max_sitemap_urls >= 1
