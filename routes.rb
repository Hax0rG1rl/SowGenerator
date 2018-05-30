require 'sinatra'
require 'json'
require './model/master'
require './plugins/SowGenerator/master_services'

def get_plugin_options
  plugin_options = JSON.parse(File.read('./plugins/SowGenerator/config.json'))
end

# this function determines if the report is using a sow template
# pass it the report object (result from get_report(id))
def is_report_sow(report)

  @templates = Xslt.all(order: [:report_type.asc])

  # which xslt is this report assigned to
  @templates.each do |template|
    if template.report_type == report.report_type

      # is template report_type a sow template
      DataMapper.repository(:services) {
        @xsltsow = XsltSows.first(:xslt_id => template.id)
        if @xsltsow
          # return true and break loop
          return true
          break
        end
      }

    end
  end

  # default to false
  return false
end


class Server < Sinatra::Application
  config_options = JSON.parse(File.read('./config.json'))

  configure do
    set :haml, :layout => :'../plugins/SowGenerator/views/layout'
  end

  # override add template route
  get '/admin/templates/add' do
    redirect to('/no_access') unless is_administrator?

    @admin = true

    haml :'../plugins/SowGenerator/views/add_template', :encode_html => true
  end

  # the only difference in this route is the addition of record in the xsltsow table
  # Manage Templated Reports
  post '/admin/templates/add' do
    redirect to('/no_access') unless is_administrator?

    @admin = true

    xslt_file = "./templates/#{rand(36**36).to_s(36)}.xslt"

    redirect to('/admin/templates/add') unless params[:file]

    # reject if the file is above a certain limit
    if params[:file][:tempfile].size > 100_000_000
      return 'File too large. 10MB limit'
    end

    docx = "./templates/#{rand(36**36).to_s(36)}.docx"
    File.open(docx, 'wb') { |f| f.write(params[:file][:tempfile].read) }

    error = false
    detail = ''
    begin
      xslt = generate_xslt(docx)
      xslt_components = generate_xslt_components(docx)
    rescue ReportingError => detail
      error = true
    end

    if error
      "The report template you uploaded threw an error when parsing:<p><p> #{detail.errorString}"
    else
      # open up a file handle and write the attachment
      File.open(xslt_file, 'wb') { |f| f.write(xslt) }
      # extract the screenshot names from the file
      screenshot_names = xslt.scan(/\[!!(.*?)!!\]/)
      # delete the file data from the attachment
      datax = {}
      # to prevent traversal we hardcode this
      datax['docx_location'] = docx.to_s
      datax['xslt_location'] = xslt_file.to_s
      datax['description'] =	params[:description]
      datax['report_type'] = params[:report_type]
      datax['screenshot_names'] = screenshot_names.join(',')
      data = url_escape_hash(datax)
      data['finding_template'] = params[:finding_template] ? true : false
      data['status_template'] = params[:status_template] ? true : false

      @template = Xslt.first(report_type: data['report_type'])

      if @template
        @template.update(xslt_location: data['xslt_location'], docx_location: data['docx_location'], description: data['description'], screenshot_names: data['screenshot_names'])
        @template.components.destroy
      else
        @template = Xslt.new(data)
        @template.save
      end

      # track if template is a sow in the SowGenerator plugin db
      if params[:sow_template]
        xsltsow = {}
        xsltsow['xslt_id'] = @template.id
        DataMapper.repository(:services) {
          @sowtemplate = XsltSows.new(xsltsow)
          @sowtemplate.save
        }
      end

      # create a xslt file for each component
      list_components_files = []
      xslt_components.each do |component_name, component_xslt|
        componentHash = {}
        componentHash['xslt_location'] = "./templates/#{rand(36**36).to_s(36)}.xslt"
        componentHash['name'] = component_name
        componentHash['xslt'] = @template
        File.open(componentHash['xslt_location'], 'wb') { |f| f.write(component_xslt) }
        list_components_files.push(componentHash)
      end

      # insert components into the db
      list_components_files.each do |component|
        @component = Xslt_component.new(component)
        @component.save
      end
      redirect to('/admin/templates')

      haml :'../plugins/SowGenerator/views/add_template', :encode_html => true

    end
  end

  # Manage Templated Reports
  get '/admin/templates/:id/edit' do
    redirect to('/no_access') unless is_administrator?

    @admin = true
    @template = Xslt.first(id: params[:id])

    haml :'../plugins/SowGenerator/views/edit_template', :encode_html => true
  end

  # Manage Templated Reports
  post '/admin/templates/edit' do
    redirect to('/no_access') unless is_administrator?

    @admin = true
    template = Xslt.first(id: params[:id])

    xslt_file = template.xslt_location

    redirect to("/admin/templates/#{params[:id]}/edit") unless params[:file]

    # reject if the file is above a certain limit
    if params[:file][:tempfile].size > 100_000_000
      return 'File too large. 10MB limit'
    end

    docx = "./templates/#{rand(36**36).to_s(36)}.docx"
    File.open(docx, 'wb') { |f| f.write(params[:file][:tempfile].read) }

    error = false
    detail = ''
    begin
      xslt = generate_xslt(docx)
      xslt_components = generate_xslt_components(docx)
    rescue ReportingError => detail
      error = true
    end

    if error
      "The report template you uploaded threw an error when parsing:<p><p> #{detail.errorString}"
    else

      # open up a file handle and write the attachment
      File.open(xslt_file, 'wb') { |f| f.write(xslt) }
      # extract the screenshot names from the file
      screenshot_names = xslt.scan(/\[!!(.*?)!!\]/)
      # delete the file data from the attachment
      datax = {}
      # to prevent traversal we hardcode this
      datax['docx_location'] = docx.to_s
      datax['xslt_location'] = xslt_file.to_s
      datax['description'] =	params[:description]
      datax['report_type'] = params[:report_type]
      datax['screenshot_names'] = screenshot_names.join(',')
      data = url_escape_hash(datax)
      data['finding_template'] = params[:finding_template] ? true : false
      data['status_template'] = params[:status_template] ? true : false

      @template = Xslt.first(report_type: data['report_type'])

      if @template
        @template.update(xslt_location: data['xslt_location'], docx_location: data['docx_location'], description: data['description'], screenshot_names: data['screenshot_names'])
        @template.components.destroy
      else
        @template = Xslt.new(data)
        @template.save
      end

      if params[:sow_template]
        xsltsow = {}
        xsltsow['xslt_id'] = @template.id
        DataMapper.repository(:services) {
          @sowtemplate = XsltSows.new(xsltsow)
          @sowtemplate.save
        }
      end

      # create a xslt file for each component
      list_components_files = []
      xslt_components.each do |component_name, component_xslt|
        componentHash = {}
        componentHash['xslt_location'] = "./templates/#{rand(36**36).to_s(36)}.xslt"
        componentHash['name'] = component_name
        componentHash['xslt'] = @template
        File.open(componentHash['xslt_location'], 'wb') { |f| f.write(component_xslt) }
        list_components_files.push(componentHash)
      end

      # insert components into the db
      list_components_files.each do |component|
        @component = Xslt_component.new(component)
        @component.save
      end
      redirect to('/admin/templates')
    end
  end

  # List Templated Service Offerings
  get '/master/services' do
    redirect to("/no_access") if not is_administrator?

    DataMapper.repository(:services) {
      @services = TemplateServices.all(:order => [:title.asc])
    }
    @master = true
    @sow = true
    @plugin_options = get_plugin_options

    haml :'../plugins/SowGenerator/views/services_list', :encode_html => true
  end

  # Create a new templated service offering
  get '/master/services/new' do
    redirect to("/no_access") if not is_administrator?

    DataMapper.repository(:services) {
      @services = TemplateServices.all(:order => [:title.asc])
    }
    @master = true
    @sow = true
    @plugin_options = get_plugin_options

    haml :'../plugins/SowGenerator/views/create_service', :encode_html => true
  end

  # Create the service in the DB
  post '/master/services/new' do
    redirect to("/no_access") if not is_administrator?

    @master = true
    @sow = true

    data = url_escape_hash(request.POST)

    DataMapper.repository(:services) {
      @service = TemplateServices.new(data)
      @service.save
    }

    redirect to('/master/services')
  end

  # Edit the templated service
  get '/master/services/:id/edit' do
      redirect to("/no_access") if not is_administrator?

      @master = true
      @sow = true

      # Check for kosher name in report name
      id = params[:id]

      # Query for all Findings
      DataMapper.repository(:services) {
        @service = TemplateServices.first(:id => id)
      }
      @templates = Xslt.all()

      if @service == nil
          return "No Such service"
      end

      @plugin_options = get_plugin_options

      haml :'../plugins/SowGenerator/views/services_edit', :encode_html => true
  end

  # Edit a service offering
  post '/master/services/:id/edit' do
      redirect to("/no_access") if not is_administrator?

      @master = true
      @sow = true

      # Check for kosher name in report name
      id = params[:id]

      # Query for all Findings
      DataMapper.repository(:services) {
        @services = TemplateServices.first(:id => id)
      }

      if @services == nil
          return "No Such Finding"
      end

      data = url_escape_hash(request.POST)

      # Update the finding with templated finding stuff
      DataMapper.repository(:services) {
        @services.update(data)
      }

      redirect to("/master/services")
  end

  # Delete a template service offering
  get '/master/services/:id/delete' do
      redirect to("/no_access") if not is_administrator?

      @master = true
      @sow = true

      # Check for kosher name in report name
      id = params[:id]

      # Query for all Findings
      DataMapper.repository(:services) {
        @services = TemplateServices.first(:id => id)
      }

      if @services == nil
          return "No Such Finding"
      end

      # Update the finding with templated finding stuff
      DataMapper.repository(:services) {
        @services.destroy
      }

      redirect to("/master/services")
  end

  # Edit the Report's main information; Name, Consultant, etc.
  get '/report/:id/edit' do
    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)
    @templates = Xslt.all(order: [:report_type.asc])
    @plugin_side_menu = get_plugin_list
    @assessment_types = config_options['report_assessment_types']
    @languages = config_options['languages']
    @risk_scores = %w[Risk DREAD CVSS CVSSv3 RiskMatrix]

    # is this report a sow
    @sow = is_report_sow(@report)

    return 'No Such Report' if @report.nil?

    @report.update(scoring: set_scoring(config_options)) unless @report.scoring

    haml :report_edit, encode_html: true
  end

  # Edit the Report's Current services
  get '/report/:id/services' do
      redirect to("/") unless valid_session?

      @sow = true
      @report = true
      id = params[:id]

      # Query for the first report matching the report_name
      @report = get_report(id)

      if @report == nil
          return "No Such Report"
      end

      # Query for the services that match the report_id
      DataMapper.repository(:services) {
        @services = Services.all(:report_id => id)
      }

      haml :'../plugins/SowGenerator/views/services_list', :encode_html => true
  end

  # Add a service to the report
  get '/report/:id/services_add' do
      redirect to("/") unless valid_session?

      @sow = true
      @plugin_options = get_plugin_options

      # Check for kosher name in report name
      id = params[:id]

      # Query for the first report matching the report_name
      @report = get_report(id)

      if @report == nil
          return "No Such Report"
      end

      # Query for all Services
      DataMapper.repository(:services) {
        @services = TemplateServices.all(:order => [:title.asc])
      }

      haml :'../plugins/SowGenerator/views/services_add', :encode_html => true
  end

  # Add a service to the report
  post '/report/:id/services_add' do
      redirect to("/") unless valid_session?

      @sow = true

      # Check for kosher name in report name
      id = params[:id]

      # Query for the first report matching the report_name
      @report = get_report(id)

      if @report == nil
          return "No Such Report"
      end

      redirect to("/report/#{id}/services") unless params[:services]

      params[:services].each do |service|
          DataMapper.repository(:services) {
            @templated_service = TemplateServices.first(:id => service.to_i)
          }

          @templated_service.id = nil
          attr = @templated_service.attributes
          attr["master_id"] = service.to_i
          puts attr
          DataMapper.repository(:services) {
            @newservice = Services.new(attr)
            @newservice.report_id = id
            @newservice.save
          }
      end

      DataMapper.repository(:services) {
        @services = Services.all(:report_id => id)
      }

      haml :'../plugins/SowGenerator/views/services_list', :encode_html => true
  end

  # Create a new service in the report
  get '/report/:id/services/new' do
    # Query for the first report matching the report_name
    @report = get_report(params[:id])
    return 'No Such Report' if @report.nil?

    @sow = true
    @plugin_options = get_plugin_options

    # attachments autocomplete work
    temp_attaches = Attachments.all(report_id: params[:id])
    @attaches = []
    temp_attaches.each do |ta|
      next unless ta.description =~ /png/i || ta.description =~ /jpg/i
      @attaches.push(ta.description)
    end

    haml :'../plugins/SowGenerator/views/create_service', encode_html: true
  end

  # Create the Service in the DB
  post '/report/:id/services/new' do
    error = mm_verify(request.POST)
    return error if error.size > 1
    data = url_escape_hash(request.POST)

    @sow = true

    id = params[:id]
    @report = get_report(id)
    return 'No Such Report' if @report.nil?

    data['report_id'] = id

    DataMapper.repository(:services) {
        @services = Services.new(data)
        @services.save
    }

    # for a parameter_pollution on report_id
    redirect to("/report/#{id}/services")
  end

  # Edit the service offering in a report
  get '/report/:id/services/:services_id/edit' do
    redirect to("/") unless valid_session?

    @sow =true
    @plugin_options = get_plugin_options

    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    service_id = params[:services_id]

    # Query for all Services
    DataMapper.repository(:services) {
        @service = Services.first(:report_id => id, :id => service_id)
    }

    if @service == nil
        return "No Such Service"
    end

    haml :'../plugins/SowGenerator/views/services_edit', :encode_html => true
  end

  # Edit the service offering in a report
  post '/report/:id/services/:services_id/edit' do
      redirect to("/") unless valid_session?

      @sow = true
      @plugin_options = get_plugin_options

      # Check for kosher name in report name
      id = params[:id]

      # Query for the report
      @report = get_report(id)

      if @report == nil
          return "No Such Report"
      end

      service_id = params[:services_id]

      # Query for all Services
      DataMapper.repository(:services) {
          @service = Services.first(:report_id => id, :id => service_id)
      }

      if @service == nil
          return "No Such Service"
      end

      data = url_escape_hash(request.POST)

      # Update the service with templated services stuff
      @service.update(data)

      redirect to("/report/#{id}/services")
  end


  # Remove a service offering from the report
  get '/report/:id/services/:services_id/remove' do
      redirect to("/") unless valid_session?

      @sow = true

      # Check for kosher name in report name
      id = params[:id]

      # Query for the report
      @report = get_report(id)

      if @report == nil
          return "No Such Report"
      end

      service_id = params[:services_id]

      # Query for service
      DataMapper.repository(:services) {
          @service = Services.first(:report_id => id, :id => service_id)
      }

      if @service == nil
          return "No Such Service"
      end

      # delete service
      @service.destroy

      redirect to("/report/#{id}/services")
  end

  # Generate the report
  get '/report/:id/generate' do
    id = params[:id]

    # Query for the report
    @report = get_report(id)

    return 'No Such Report' if @report.nil?

    @report.update(scoring: set_scoring(config_options)) unless @report.scoring

    user = User.first(username: get_username)

    if user
      @report.consultant_name = user.consultant_name
      @report.consultant_phone = user.consultant_phone
      @report.consultant_email = user.consultant_email
      @report.consultant_title = user.consultant_title
      @report.consultant_company = user.consultant_company

    else
      @report.consultant_name = ''
      @report.consultant_phone = ''
      @report.consultant_email = ''
      @report.consultant_title = ''
      @report.consultant_company = ''

    end
    @report.save

    # is report a sow
    @sow = is_report_sow(@report)



    ## We have to do some hackery here for wordml
    findings_xml = ''

    if @sow
      DataMapper.repository(:services) {
        @findings = Services.all(:report_id => id)
      }
      findings_xml << '<services_list>'
    else
      findings_xml << '<findings_list>'
      @findings, @dread, @cvss, @cvssv3, @risk, @riskmatrix = get_scoring_findings(@report)
    end

    finding_number = 1

    @findings.each do |finding|
      # only findings need numbering
      unless @sow
        finding.finding_number = finding_number
      end

      # This flags new or edited findings
      if finding.master_id
        if @sow
          DataMapper.repository(:services) {
            # we use @masterfinding instead of master b/c we need to make it an instance variable without clashing with @master for template viewing
            @masterfinding = TemplateServices.first(:id => finding.master_id)
          }
          if @masterfinding
            finding.description = compare_text(finding.description, @masterfinding.description)
          else
            finding.description = compare_text(finding.description, nil)
          end
        else
          @masterfinding = TemplateFindings.first(:id => finding.master_id)
          if @masterfinding
            finding.overview = compare_text(finding.overview, @masterfinding.overview)
            finding.remediation = compare_text(finding.remediation, @masterfinding.remediation)
          else
            finding.overview = compare_text(finding.overview, nil)
            finding.remediation = compare_text(finding.remediation, nil)
          end
        end
      else
        if @sow
          finding.description = compare_text(finding.description, nil)
        else
          finding.overview = compare_text(finding.overview, nil)
          finding.remediation = compare_text(finding.remediation, nil)
        end
      end
      findings_xml << finding.to_xml

      # only findings need numbering
      unless @sow
        finding_number += 1
      end

    end

    if @sow
      findings_xml << '</services_list>'
    else
      findings_xml << '</findings_list>'
    end

    # Replace the stub elements with real XML elements
    findings_xml = meta_markup_unencode(findings_xml, @report)

    # check if the report has user_defined variables
    if @report.user_defined_variables
      # we need the user defined variables in xml
      udv_hash = JSON.parse(@report.user_defined_variables)
    end

    # adding the udvs to the XML

    # update udv_hash with findings totals
    unless @sow
      udv_hash = add_findings_totals(udv_hash, @findings, config_options)

      udv = "<udv>\n"
      udv_hash.each do |key, value|
        udv << "<#{key}>"
        udv << value.to_s
        udv << "</#{key}>\n"
      end
      udv << "</udv>\n"
    end

    # adding the udos to the XML
    udo_xml = "<udo>\n"
    udo_templates = UserDefinedObjectTemplates.all
    udo_templates.each do |udo_template|
      # we only add the udos that are linked to the current report, and linked to its respective template
      udos = UserDefinedObjects.all(report_id: @report.id, template_id: udo_template.id)
      udos.each do |udo|
        udo_xml << "\t<#{udo_template.type.downcase.tr(' ', '_')}>\n"
        properties = JSON.parse(udo.udo_properties)
        properties.each do |prop, value|
          udo_xml << "\t\t<#{prop.downcase.tr(' ', '_')}>"
          udo_xml << value.to_s
          udo_xml << "</#{prop.downcase.tr(' ', '_')}>\n"
        end
        udo_xml << "\t</#{udo_template.type.downcase.tr(' ', '_')}>\n"
      end
    end
    udo_xml << "</udo>\n"

    # if msf connection up, we add services and hosts to the xml
    unless @sow
      services_xml = ''
      if (msfsettings = RemoteEndpoints.first(report_id: @report.id))
        if (rpc = msfrpc(@report.id))
          res = rpc.call('console.create')
          rpc.call('db.set_workspace', msfsettings.workspace)
          # We create the XML from the opened services. onlyup undocumented but it does exist
          res = rpc.call('db.services', limit: 10_000, only_up: true)
          msfservices = res['services']
          services_xml_raw = Nokogiri::XML::Builder.new do |xml|
            xml.services do
              msfservices.each do |msfservice|
                xml.service do
                  msfservice.each do |key, value|
                    xml.send "#{key}_", value
                  end
                end
              end
            end
          end
          services_xml = services_xml_raw.doc.root.to_xml
          # we create the XML from the hosts found.
          res = rpc.call('db.hosts', limit: 10_000)
          msfhosts = res['hosts']
          hosts_xml_raw = Nokogiri::XML::Builder.new do |xml|
            xml.hosts do
              msfhosts.each do |msfhost|
                xml.host do
                  msfhost.each do |key, value|
                    xml.send "#{key}_", value
                  end
                end
              end
            end
          end
          hosts_xml = hosts_xml_raw.doc.root.to_xml
        end
      end
    end
    # we bring all xml together
    report_xml = "<report>#{@report.to_xml}#{udv}#{findings_xml}#{udo_xml}#{services_xml}#{hosts_xml}</report>"
    noko_report_xml = Nokogiri::XML(report_xml)
    #no use to go on with report generation if report XML is malformed
    if !noko_report_xml.errors.empty?
      noko_report_xml.errors.each do |error|
        error = CGI.escapeHTML(error.to_s)
      end
      return "<p>The following error(s) were found in report XML file : </p>#{noko_report_xml.errors.join('<br/>')}<p>This is most often because of malformed metamarkup in findings."
    end

    xslt_elem = Xslt.first(report_type: @report.report_type)

    # Push the finding from XML to XSLT
    xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

    docx_xml = xslt.transform(Nokogiri::XML(report_xml))

    # We use a temporary file with a random name
    rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

    # Create a temporary copy of the word doc
    FileUtils.copy_file(xslt_elem.docx_location, rand_file)

    list_components = {}
    xslt_elem.components.each do |component|
      xslt = Nokogiri::XSLT(File.read(component.xslt_location))
      list_components[component.name] = xslt.transform(Nokogiri::XML(report_xml))
    end
    ### IMAGE INSERT CODE
    if docx_xml.to_s =~ /\[!!/
      # first we read in the current [Content_Types.xml]
      content_types = read_rels(rand_file, '[Content_Types].xml')

      # add the png and jpg handling to end of content types document
      if content_types !~ /image\/jpg/
        content_types = content_types.sub('</Types>', '<Default Extension="jpg" ContentType="image/jpg"/></Types>')
      end
      if content_types !~ /image\/png/
        content_types = content_types.sub('</Types>', '<Default Extension="png" ContentType="image/png"/></Types>')
      end
      if content_types !~ /image\/jpeg/
        content_types = content_types.sub('</Types>', '<Default Extension="jpeg" ContentType="image/jpeg"/></Types>')
      end

      docx_modify(rand_file, content_types, '[Content_Types].xml')

      # replace all [!! image !!] in the document
      imgs = docx_xml.to_s.split('[!!')
      docx = imgs.first
      imgs.delete_at(0)

      imgs.each do |image_i|
        name = image_i.split('!!]').first.delete(' ')
        end_xml = image_i.split('!!]').last

        # search for the image in the attachments
        image = Attachments.first(description: name, report_id: id)

        # tries to prevent breakage in the case image dne
        if image
          # inserts the image
          docx = image_insert(docx, rand_file, image, end_xml)
        else
          docx << end_xml
        end
      end
    else
      # no images in finding
      docx = docx_xml.to_s
    end
    #### END IMAGE INSERT CODE

    # Get hyperlinks and References
    hyperlinks = updateHyperlinks(docx)
    # Update _rels directrory
    rels_file =  read_rels(rand_file, 'word/_rels/document.xml.rels')
    # Noko syntax rels
    noko_rels =  Nokogiri::XML(rels_file)
    urls = hyperlinks['urls']
    id = hyperlinks['id']
    for i in 0..id.length - 1
      url =  urls[i]
      cid =  id[i]
      noko_rels.root.first_element_child.after("<Relationship Id=\"#{cid}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"#{url.delete(' ')}\" TargetMode=\"External\"/>")
    end

    content_to_write = noko_rels.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML).strip
    # Edit Relationships file
    write_rels(rand_file, 'word/_rels/document.xml.rels', content_to_write)
    # Update hyperlinks
    docx = hyperlinks['xmlText']

    docx_modify(rand_file, docx, 'word/document.xml')

    list_components.each do |name, xml|
      docx_modify(rand_file, xml.to_s, name)
    end

    serpico_log("Report generation attempted, Report Name: #{@report.report_name} #{rand_file} #{xslt_elem.xslt_location}")
    send_file rand_file, type: 'docx', filename: "#{@report.report_name}.docx"
  end
end
