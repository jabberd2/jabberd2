#!/usr/bin/ruby

# bdb2msql.rb - Migrate the jabberd2 data in sm.db and authreg.db to MySQL
#
# Warning! This tool has not widely been tested! Use at your own risk
#
# Copyright (C) 2007 by Daniel Willmann <daniel@totalueberwachung.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Public License as published by
# the Free Software Foundation; version 2 of the license.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser Public License for more details.

require 'optparse'
require 'mysql'
require 'bdb'


class Table
  def initialize(name)
    @table = name
    @map = Array.new()
  end
  def name
    @table
  end
  def self.FORMAT
    return @FORMAT
  end
  def FORMAT
    return self.class.FORMAT
  end
  def self.FIELDS
    return @FIELDS
  end
  def FIELDS
    return self.class.FIELDS
  end
  def feeddb(db)
    db.each_key { |dbkey|
      map = Hash.new()
      list = db[dbkey].unpack(self.class.FORMAT)
      list.each_index { |index|
        map[self.FIELDS[index]] = list[index]
      }
      @map << map
    }
  end
  def to_sql
    def escape(str)
      if (str.class == String)
        "'" + Mysql.quote(str) + "'"
      else
        str
      end
    end

    tmplist = [ ]

    @map.each { |row|
      tmplist << "INSERT INTO `#{@table}` (`#{row.keys.join('`, `')}`) VALUES (#{row.values.collect{|str| escape(str)}.join(', ')})"
    }
    return tmplist
  end
end

class Authreg <Table
  @FIELDS = ["username", "realm", "password"]
  @FORMAT = "A257 A257 A257" # xx for padding so that the integer is aligned
#  @FIELDS = ["username", "realm", "password", "token", "sequence", "hash"]
#  @FORMAT = "A257 A257 A257 A11 xxi A41" # xx for padding so that the integer is aligned
end

class Sm <Table
  def feeddb(db)
    db.each { |colown, pairs|
      map = { }
      map['collection-owner'] = colown

      if (pairs == nil)
#        puts "No entry for collection-owner == #{colown}"
        next
      end

      while (pairs.length > 0)
        key = pairs[0...pairs.index(0)]
        pairs = pairs[pairs.index(0)+1..-1]

        vtype = pairs.unpack('i')[0]
        pairs = pairs[4..-1]

	case vtype	
	when 0,1
	  value = pairs.unpack('i')
	  pairs = pairs[4..-1]
	when 2,3
	  value = pairs[0...pairs.index(0)]
	  pairs = pairs[pairs.index(0)+1..-1]
	else
	  raise "Invalid type encountered #{vtype}! Key was #{key}"
	end

	map[key] = value
#        puts "Key #{key}"
#        puts "Type #{vtype}"
#        puts "Value #{value}"
      end
#      puts map.inspect    

      @map << map
    }
  end
end


options = {:user => 'jabberd2', :host => 'localhost', :db => 'jabberd2', :apply => false}

opts = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <bdbdir>"
  opts.on("-a", "--apply", "Modify the mysql database") do |v|
    options[:apply] = v
  end
  opts.on("-u", "--user <username>", "Mysql username") do |v|
    options[:user] = v
  end
  opts.on("-p", "--password <password>", "Mysql password") do |v|
    options[:password] = v
  end
  opts.on("-h", "--host <hostname>", "Host the mysql server runs on") do |v|
    options[:host] = v
  end
  opts.on("-d", "--db <database>", "Which database to use") do |v|
    options[:db] = v
  end
end

opts.parse!

if (ARGV.length == 0)
  puts opts.help
  exit 1
end

authregfile = ARGV[0] + "authreg.db"
smfile = ARGV[0] + "sm.db"
tables = [ ]

puts "Looking for authreg.db in #{authregfile}"

db = BDB::Btree.open(authregfile, nil, BDB::RDONLY)
authreg = Authreg.new('authreg')

db.each_key { |sub|
  subdb = BDB::Hash.open(authregfile, sub, BDB::RDONLY)
  authreg.feeddb(subdb)
}

tables << authreg

puts "Looking for sm.db in #{smfile}"

db = BDB::Btree.open(smfile, nil, BDB::RDONLY)

db.each_key { |sub|
#  puts "Found Table #{sub}"
  sm = Sm.new(sub)
  subdb = BDB::Hash.open(smfile, sub, BDB::RDONLY)
  sm.feeddb(subdb)
  tables << sm
}

if (options[:apply])
  mydb = Mysql.real_connect(options[:host], options[:user], options[:password], options[:db])
end

tables.each { |tbl|
  if (!options[:apply])
    puts "Table #{tbl.name}"
    tbl.to_sql.each {|statement|
      puts statement
    }
  else
    puts "Adding statements for table #{tbl.name}"
    tbl.to_sql.each {|statement|
      mydb.query(statement)
    }
  end
}

if (options[:apply])
  puts "Database updated"
else
  puts "Not modified the database"
end
