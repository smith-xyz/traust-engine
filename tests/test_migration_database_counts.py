from traust_engine.corpus.migration_database import MigrationTarget


class Result:
    def __init__(self, values):
        self.values = values

    def __iter__(self):
        return iter(self.values)

    def fetchone(self):
        return self.values[0]


class Connection:
    def execute(self, statement):
        if "information_schema" in statement:
            assert "t.table_type='BASE TABLE'" in statement
            assert "JOIN information_schema.tables" in statement
            return Result([("artifact_binding",), ("report",)])
        return Result([(1,)])


def test_postgres_counts_exclude_derived_views():
    database = object.__new__(MigrationTarget)
    database.conn, database.dialect = Connection(), "postgres"
    assert database.counts() == {"artifact_binding": 1, "artifact_evidence": 1, "report": 1}
