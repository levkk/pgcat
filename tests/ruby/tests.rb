# frozen_string_literal: true

require 'active_record'
require 'pg'

$stdout.sync = true

# Uncomment these two to see all queries.
# ActiveRecord.verbose_query_logs = true
# ActiveRecord::Base.logger = Logger.new(STDOUT)

ActiveRecord::Base.establish_connection(
  adapter: 'postgresql',
  host: '127.0.0.1',
  port: 6432,
  username: 'sharding_user',
  password: 'sharding_user',
  database: 'sharded_db',
  application_name: 'testing_pgcat',
  prepared_statements: false, # Transaction mode
  advisory_locks: false # Same
)

class TestSafeTable < ActiveRecord::Base
  self.table_name = 'test_safe_table'
end

class ShouldNeverHappenException < RuntimeError
end

class CreateSafeShardedTable < ActiveRecord::Migration[7.0]
  # Disable transasctions or things will fly out of order!
  disable_ddl_transaction!

  SHARDS = 3

  def up
    SHARDS.times do |x|
      # This will make this migration reversible!
      connection.execute "SET SHARD TO '#{x.to_i}'"
      connection.execute "SET SERVER ROLE TO 'primary'"

      connection.execute <<-SQL
        CREATE TABLE test_safe_table (
          id BIGINT PRIMARY KEY,
          name VARCHAR,
          description TEXT
        ) PARTITION BY HASH (id);

        CREATE TABLE test_safe_table_data PARTITION OF test_safe_table
        FOR VALUES WITH (MODULUS #{SHARDS.to_i}, REMAINDER #{x.to_i});
      SQL
    end
  end

  def down
    SHARDS.times do |x|
      connection.execute "SET SHARD TO '#{x.to_i}'"
      connection.execute "SET SERVER ROLE TO 'primary'"
      connection.execute 'DROP TABLE test_safe_table CASCADE'
    end
  end
end

SHARDS = 3

2.times do
  begin
    CreateSafeShardedTable.migrate(:down)
  rescue Exception
    puts "Tables don't exist yet"
  end

  CreateSafeShardedTable.migrate(:up)

  SHARDS.times do |x|
    TestSafeTable.connection.execute "SET SHARD TO '#{x.to_i}'"
    TestSafeTable.connection.execute "SET SERVER ROLE TO 'primary'"
    TestSafeTable.connection.execute "TRUNCATE #{TestSafeTable.table_name}"
  end

  # Equivalent to Makara's stick_to_master! except it sticks until it's changed.
  TestSafeTable.connection.execute "SET SERVER ROLE TO 'primary'"

  200.times do |x|
    x += 1 # Postgres ids start at 1
    TestSafeTable.connection.execute "SET SHARDING KEY TO '#{x.to_i}'"
    TestSafeTable.create(id: x, name: "something_special_#{x.to_i}", description: "It's a surprise!")
  end

  TestSafeTable.connection.execute "SET SERVER ROLE TO 'replica'"

  100.times do |x|
    x += 1 # 0 confuses our sharding function
    TestSafeTable.connection.execute "SET SHARDING KEY TO '#{x.to_i}'"
    TestSafeTable.find_by_id(x).id
  end

  # Will use the query parser to direct reads to replicas
  TestSafeTable.connection.execute "SET SERVER ROLE TO 'auto'"

  100.times do |x|
    x += 101
    TestSafeTable.connection.execute "SET SHARDING KEY TO '#{x.to_i}'"
    TestSafeTable.find_by_id(x).id
  end
end

# Test wrong shard
TestSafeTable.connection.execute "SET SHARD TO '1'"
begin
  TestSafeTable.create(id: 5, name: 'test', description: 'test description')
  raise ShouldNeverHappenException('Uh oh')
rescue ActiveRecord::StatementInvalid
  puts 'OK'
end

# Test evil clients
def poorly_behaved_client
  conn = PG::connect("postgres://sharding_user:sharding_user@127.0.0.1:6432/sharded_db?application_name=testing_pgcat")
  conn.async_exec 'BEGIN'
  conn.async_exec 'SELECT 1'

  conn.close
  puts 'Bad client ok'
end

25.times do
  poorly_behaved_client
end


# Test reader/writer endpoints
def test_reader_writer_endpoints
  conn = PG::connect("postgres://sharding_user:sharding_user@127.0.0.1:6432/sharded_db/reader?application_name=testing_pgcat")
  conn.async_exec 'BEGIN'
  conn.async_exec 'SELECT 1'
  conn.async_exec 'COMMIT'
  conn.close

  conn = PG::connect("postgres://sharding_user:sharding_user@127.0.0.1:6432/sharded_db/writer?application_name=testing_pgcat")
  conn.async_exec 'BEGIN'
  conn.async_exec 'SELECT 1'
  conn.async_exec 'COMMIT'
  conn.close

  puts 'Reader/Writer clients ok'
end

test_reader_writer_endpoints
