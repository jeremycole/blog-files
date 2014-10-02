#!/usr/bin/env ruby

require "mysql"

mode = Hash.new(false)
ARGV.each { |arg| mode[arg] = true }

m = Mysql.new("127.0.0.1", "root", "", "test", 13000)

table_name = "t"
table_name += "_shuffle" if mode["shuffle"]
table_name += "_index_before" if mode["index_before"]
table_name += "_index_after" if mode["index_after"]

puts "Creating #{table_name}..."

m.query("DROP TABLE IF EXISTS #{table_name}")
m.query("CREATE TABLE #{table_name} (i INT UNSIGNED NOT NULL, s CHAR(200) NOT NULL, PRIMARY KEY (i)) ENGINE=InnoDB")
if mode["index_before"]
  m.query("ALTER TABLE #{table_name} ADD INDEX s_before (s)")
end

chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
rows = (1..50000).to_a

rows = rows.shuffle if mode["shuffle"]

rows.each_with_index do |i, index|
  s = chars.shuffle.join + chars.shuffle.join
  m.query("INSERT INTO #{table_name} (i, s) VALUES (#{i}, REPEAT('#{s}', 20))")
  puts "Inserted #{index} rows..." if index % 10000 == 0
end

if mode["index_after"]
  m.query("ALTER TABLE #{table_name} ADD INDEX s_after (s)")
end
