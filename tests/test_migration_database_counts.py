from traust_engine.corpus.migration_database import RehearsalDatabase


class Result:
    def __init__(self, values):
        self.values = values

    def fetchall(self):
        return self.values

    def fetchone(self):
        return self.values[0]


class Connection:
    def execute(self, statement):
        if isinstance(statement, str):
            assert "t.table_type='BASE TABLE'" in statement
            assert "JOIN information_schema.tables" in statement
            return Result([("artifact_binding",), ("report",)])
        return Result([(1,)])


def test_postgres_counts_exclude_derived_views():
    database = object.__new__(RehearsalDatabase)
    database.conn = Connection()
    assert database.counts() == {"artifact_binding": 1, "artifact_evidence": 1, "report": 1}
