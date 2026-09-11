"""Tests for SqlInjectionStep."""

from unittest.mock import AsyncMock, MagicMock

from steps.active.sql_injection_step import (
    SqlInjectionStep,
    engine_delay_signature,
    match_sql_error,
)


class TestMatchSqlError:
    def test_mysql(self):
        hit = match_sql_error("You have an error in your SQL syntax near...")
        assert hit and hit[0] == "MySQL"

    def test_postgres(self):
        assert match_sql_error("pg_query(): Query failed")[0] == "PostgreSQL"

    def test_sqlite(self):
        assert match_sql_error("sqlite_master table")[0] == "SQLite"

    def test_no_error(self):
        assert match_sql_error("<html>normal page</html>") is None


class TestEngineDelaySignature:
    def test_labels(self):
        assert engine_delay_signature("SLEEP(4)") == "MySQL SLEEP"
        assert engine_delay_signature("WAITFOR DELAY") == "MSSQL WAITFOR"
        assert engine_delay_signature("pg_sleep(4)") == "PostgreSQL pg_sleep"


class TestSqlInjectionStep:
    def make_step(self, mock_http, mock_target, mock_config, enabled=True,
                  time_based=False):
        mock_config.active_enabled = enabled
        mock_config.active_max_requests = 50
        mock_config.active_delay = 0.0
        mock_config.active_max_params = 10
        mock_config.active_time_based = time_based
        return SqlInjectionStep(target=mock_target, config=mock_config, http=mock_http)

    async def test_disabled_by_gate(self, mock_http, mock_target, mock_config):
        step = self.make_step(mock_http, mock_target, mock_config, enabled=False)
        assert await step.run() == []

    async def test_no_params(self, mock_http, mock_target, mock_config):
        mock_http.request = AsyncMock(
            return_value=MagicMock(status_code=200, text="<p>static</p>")
        )
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []

    async def test_error_signature_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            if "'" in url:
                return MagicMock(status_code=200,
                                 text="Warning: mysql_query(): error in your SQL syntax")
            return MagicMock(status_code=200,
                             text='<a href="/item?id=1">link</a>')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        findings = await step.run()
        assert any("SQL error" in f.title for f in findings)

    async def test_baseline_error_not_reported(self, mock_http, mock_target, mock_config):
        async def requestor(method, url, **kwargs):
            return MagicMock(status_code=200,
                             text='<a href="/item?id=1">l</a> '
                                  'error in your SQL syntax')

        mock_http.request = AsyncMock(side_effect=requestor)
        step = self.make_step(mock_http, mock_target, mock_config)
        assert await step.run() == []
