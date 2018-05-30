require 'data_mapper'
require 'dm-migrations'

# /plugins/SowGenerator/services.db

# Initialize the Master DB
DataMapper.setup(:services, "sqlite://#{Dir.pwd}/plugins/SowGenerator/services.db")

class TemplateServices
  include DataMapper::Resource

  property :id, Serial
  property :type, String, :required => true, :length => 200
  property :title, String, :required => false, :length => 200
  property :units, Integer, :required => false
  property :rate, Integer, :required => false
  property :description, String, :length => 20000, :required => false

end

class Services
  include DataMapper::Resource

  property :id, Serial
  property :type, String, :required => true, :length => 200
  property :title, String, :required => false, :length => 200
  property :report_id, Integer, :required => true
  property :master_id, Integer, :required => false
  property :service_modified, Boolean, :required => false
  property :units, Integer, :required => false
  property :rate, Integer, :required => false
  property :description, String, :length => 20000, :required => false
  property :notes, String, :length => 20000, :required => false

end

# tables holds xslts (report templates) that are sow templates
# create table "xslt_sows" ("id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "xslt_id" INTEGER NOT NULL);
class XsltSows
  include DataMapper::Resource

  property :id, Serial
  property :xslt_id, Integer, :required => true
end

DataMapper.finalize
DataMapper.repository(:services).auto_migrate!


