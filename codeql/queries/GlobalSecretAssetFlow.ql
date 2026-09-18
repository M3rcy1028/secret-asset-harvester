/**
 * @name Global database secret and asset flows
 * @description Reports literal sources that reach supported database-driver credential, host, or DSN sinks through interprocedural flow.
 * @kind problem
 * @id assetharvester/python/global-secret-asset-flow
 * @precision medium
 * @severity warning
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

class StringSource extends DataFlow::Node {
  StringSource() { exists(StrConst value | this.asCfgNode().getNode() = value) }
}

predicate isCredentialSink(DataFlow::Node sink) {
  sink = API::moduleImport("aiomysql").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("aiomysql").getMember("create_pool").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("mysql").getMember("connector").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("pymysql").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("asyncpg").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("asyncpg").getMember("create_pool").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("asyncpg").getMember("connect").getParameter(3).asSink() or
  sink = API::moduleImport("pymongo").getMember("MongoClient").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("pymssql").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("MySQLdb").getMember("connect").getParameter(2).asSink() or
  sink = API::moduleImport("peewee").getMember("PostgresqlDatabase").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("peewee").getMember("MySQLDatabase").getKeywordParameter("password").asSink()
}

predicate isAssetSink(DataFlow::Node sink) {
  sink = API::moduleImport("aiomysql").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("aiomysql").getMember("create_pool").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("mysql").getMember("connector").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("pymysql").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("asyncpg").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("asyncpg").getMember("create_pool").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("asyncpg").getMember("connect").getParameter(0).asSink() or
  sink = API::moduleImport("pymongo").getMember("MongoClient").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("pymssql").getMember("connect").getKeywordParameter("server").asSink() or
  sink = API::moduleImport("MySQLdb").getMember("connect").getParameter(0).asSink() or
  sink = API::moduleImport("peewee").getMember("PostgresqlDatabase").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("peewee").getMember("MySQLDatabase").getKeywordParameter("host").asSink()
}

predicate isDsnSink(DataFlow::Node sink) {
  sink = API::moduleImport("aiopg").getMember("connect").getParameter(0).asSink() or
  sink = API::moduleImport("psycopg").getMember("connect").getParameter(0).asSink() or
  sink = API::moduleImport("psycopg2").getMember("connect").getParameter(0).asSink() or
  sink = API::moduleImport("pyodbc").getMember("connect").getParameter(0).asSink() or
  sink = API::moduleImport("jaydebeapi").getMember("connect").getParameter(1).asSink() or
  sink = API::moduleImport("sqlalchemy").getMember("create_engine").getParameter(0).asSink()
}

module GlobalFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof StringSource }
  predicate isSink(DataFlow::Node sink) { isCredentialSink(sink) or isAssetSink(sink) or isDsnSink(sink) }
}

module GlobalFlow = TaintTracking::Global<GlobalFlowConfiguration>;

from StringSource source, DataFlow::Node sink, string role
where
  GlobalFlow::flow(source, sink) and
  ((isCredentialSink(sink) and role = "credential") or
  (isAssetSink(sink) and role = "asset") or
  (isDsnSink(sink) and role = "DSN/URI"))
select sink, "A " + role + " source reaches this database-driver sink through global data flow."
