/**
 * @name Database secret and asset flows
 * @description Reports sources that reach credential and host sinks in supported Python database drivers.
 * @kind problem
 * @id assetharvester/python/secret-asset-flow
 * @severity warning
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

predicate isPasswordSink(DataFlow::Node sink) {
  sink = API::moduleImport("aiomysql").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("aiomysql").getMember("create_pool").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("mysql.connector").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("pymysql").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("aiopg").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("asyncpg").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("asyncpg").getMember("create_pool").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("psycopg2").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("pymongo").getMember("MongoClient").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("pymssql").getMember("connect").getKeywordParameter("password").asSink() or
  sink = API::moduleImport("peewee").getMember("Database").getKeywordParameter("password").asSink()
}

predicate isHostSink(DataFlow::Node sink) {
  sink = API::moduleImport("aiomysql").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("aiomysql").getMember("create_pool").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("mysql.connector").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("pymysql").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("asyncpg").getMember("connect").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("asyncpg").getMember("create_pool").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("pymongo").getMember("MongoClient").getKeywordParameter("host").asSink() or
  sink = API::moduleImport("pymssql").getMember("connect").getKeywordParameter("server").asSink() or
  sink = API::moduleImport("peewee").getMember("Database").getKeywordParameter("host").asSink()
}

from DataFlow::Node source, DataFlow::Node sink, string role
where
  ((isPasswordSink(sink) and role = "credential") or
  (isHostSink(sink) and role = "asset"))
  and DataFlow::localFlow(source, sink)
  and source instanceof DataFlow::LocalSourceNode
select sink, "A " + role + " source (" + source.toString() + ") reaches this database sink."
