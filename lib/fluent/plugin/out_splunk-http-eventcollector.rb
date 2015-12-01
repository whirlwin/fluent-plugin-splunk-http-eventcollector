=begin

  Copyright (C) 2013 Keisuke Nishida

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.

=end

module Fluent

class SplunkHTTPEventcollectorOutput < Output
  Plugin.register_output('splunk-http-eventcollector', self)

  config_param :server, :string, :default => 'localhost:8088'
  config_param :verify, :bool, :default => true
  config_param :token, :string, :default => nil

  # Event parameters
  config_param :host, :string, :default => nil # XXX: auto-detected, nix this?
  config_param :index, :string, :default => 'main'
  config_param :source, :string, :default => '{TAG}'  # XXX nix this?
  config_param :sourcetype, :string, :default => '_json'  # XXX nix this?

  config_param :post_retry_max, :integer, :default => 5
  config_param :post_retry_interval, :integer, :default => 5

  config_param :batch_size_limit, :integer, :default => 65535
  config_param :batch_event_limit, :integer, :default => 100

  # Called on class load (class initializer)
  def initialize
    super
    $log.debug "splunk-http-eventcollector(initialize) called"
    require 'net/http/persistent'
    require 'time'
    require 'openssl'

    @idx_indexers = 0
    @indexers = []
  end  # initialize

  def configure(conf)
    super
    $log.debug "splunk-http-eventcollector(configure) called"
    
#    case @source
#    when '{TAG}'
#      @source_formatter = lambda { |tag| tag }
#    else
#      @source_formatter = lambda { |tag| @source.sub('{TAG}', tag) }
#    end

#    @time_formatter = lambda { |time| time.to_s }
    @formatter = lambda { |record|
      $log.debug "splunk-http-eventcollector(formatter) called"
      #record.to_json
      record.to_s
    }
    
    if @server.match(/,/)
      @indexers = @server.split(',')
    else
      @indexers = [@server]
    end
    if @token.match(/,/)
      @tokens = @token.split(',')
    else
      @tokens = [@token]
    end
    
    $log.debug "indexers parsed into: " + @indexers.to_s
  end  # configure

  def start
    super
    $log.debug "splunk-http-eventcollector(start) called"
    @http = Net::HTTP::Persistent.new 'fluent-plugin-splunk-http-eventcollector'
    #@http.set_debug_output $stderr # XXX
    @http.debug_output = $stderr # XXX
    @http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless @verify
    @http.override_headers['Content-Type'] = 'application/json'
    @http.override_headers['User-Agent'] = 'fluent-plugin-splunk-http-eventcollector/1.0'
    #@http.override_headers['Authorization'] = 'Splunk ' + @splunk_httpec_token
    
    $log.debug "initialized for splunk-http-eventcollector"
  end

  def shutdown
    # NOTE: call super before @http.shutdown because super may flush final output
    super
    $log.debug "splunk-http-eventcollector(shutdown) called"
    
    @http.shutdown
    $log.debug "shutdown from splunk-http-eventcollector"
  end  # shutdown

  # 'Emits' a single message. Yes this gets noisy
  def emit(tag, es, chain)
    $log.debug "splunk-http-eventcollector(emit) called"
    $log.debug "emit: tag(" + tag.class.to_s + ")=" + tag.to_s
    $log.debug "emit: es(" + es.class.to_s + ")=" + es.to_s
    $log.debug "emit: chain(" + chain.class.to_s + ")=" + chain.to_s
    
    outbuffer = ""   	# Concatenation of events to be pushed.
    running_count = 0	# Number of events concatenated in outbuffer
    
    es.each { |time,record|
      # XXX here's where my bundling goes.
      $log.debug "emit: es[] time(" + time.class.to_s + ")=" + time.to_s + " record(" + record.class.to_s + ")=" + record.to_s
      
      # NB: We don't care if tag_key or timestamp_key are set. The plugin has
      # direct access to 'tag' and 'time'
      
      # Basic object for Splunk. Note explicit type-casting just to be sure.
      splunk_object = Hash[
          "event" => record["message"],
          "time" => time.to_i,
          "source" => tag.to_s,
          "index" => @index.to_s
          ]
      
      # Check if this object will put outbuffer over the edge
      #   If it will, then push our current buffer, then clear the buffer
      # Append to the buffer and iterate again.
      if outbuffer.bytesize + json_event.bytesize > @batch_size_limit ||
         running_count >= @batch_event_limit
        $log.debug "[" + running_count.to_s + "] Reached a limit, " +
            "flushing buffer. This event size: " + json_event.bytesize.to_s +
            "B. Current buffer size: " + outbuffer.bytesize.to_s + "B / " + 
            running_count.to_s + " events. Limit: " + 
            @batch_size_limit.to_s + "B / " + @batch_event_limit.to_s + "."
        
        $log.debug "Flushing " + running_count.to_s + " events (" + 
            outbuffer.bytesize.to_s + "B) to Splunk."
        push_buffer outbuffer
        
        # Buffer has been pushed, reset and continue processing
        running_count = 0
        outbuffer = ""
      end
      
      # Append the event to the buffer and move on.
      outbuffer << json_event
      running_count += 1
    }  # es.each
    
    # Final flush
    if outbuffer.length > 0
      # Flush
      $log.debug "Flushing " + running_count.to_s + " events (" + 
          outbuffer.bytesize.to_s + "B) to Splunk."
      push_buffer outbuffer
      
      # Buffer has been pushed, reset (doesn't matter, but for sanity, and copy/paste)
      running_count = 0
      outbuffer = ""
    end
    
#    chunk_to_buffers(chunk).each do |source, messages|
#      uri = URI get_baseurl
#      post = Net::HTTP::Post.new uri.request_uri
#      post['Authorization'] = "Splunk #{token}"
#      post.body = messages.join('')
#      $log.debug "POST #{uri}"
#      # retry up to :post_retry_max times
#      1.upto(@post_retry_max) do |c|
#        response = @http.request uri, post
#        $log.debug "=>(#{c}/#{@post_retry_max} #{response.code} (#{response.message})"
#        if response.code == "200"
#          # success
#          break
#        elsif response.code.match(/^40/)
#          # user error
#          $log.error "#{uri}: #{response.code} (#{response.message})\n#{response.body}"
#          break
#        elsif c < @post_retry_max
#          # retry
#          $log.debug "#{uri}: Retrying..."
#          sleep @post_retry_interval
#          next
#        else
#          # other errors. fluentd will retry processing on exception
#          # FIXME: this may duplicate logs when using multiple buffers
#          raise "#{uri}: #{response.message}"
#        end
#      end
#    end  # chunk_to_buffers
    
    $log.debug "splunk-http-eventcollector(emit) done!"
    # Notify upstream fluentd that all is good (probably)
    chain.next
  end  # emit

  def get_baseurl
    $log.debug "splunk-http-eventcollector(get_baseurl) called"
    base_url = ''
    server = @indexers[@idx_indexers];
    @idx_indexers = (@idx_indexers + 1) % @indexers.length
    base_url = "https://#{server}/services/collector"
    base_url
  end  # get_baseurl

  def push_buffer(outbuffer)
    $log.debug "Pushing " + outbuffer.bytesize.to_s + "B to Splunk."
#    @splunk_request.body = outbuffer
#    begin
#      res = @http.request(@splunk_request)
#      if res.code.to_i == 200
#        $stderr.print green("Response: (" + res.code + "): ") +
#            res.body + "\n"
#      else
#        $stderr.print red("Response: (" + res.code + "): ") +
#            res.body + "\n"
#      end
#      # TODO check res.code==200 and res.body=='{"text":"Success","code":0}', retry?
#      # rescue
#    end
#    # Create the POST request that contains the batch.
#    @splunk_request = Net::HTTP::Post.new splunkec_uri.request_uri
#    @splunk_request["Authorization"] = "Splunk " + splunk_httpec_token
#    @splunk_request["Content-Type"] = "application/json"
#    @splunk_request["User-Agent"] = "splunk-http-eventcollector/1.1"
    uri = URI get_baseurl
    post = Net::HTTP::Post.new uri.request_uri
    post['Authorization'] = "Splunk #{@token}"
    post.body = outbuffer
    $log.debug "POST #{uri}"
    # retry up to :post_retry_max times
    1.upto(@post_retry_max) do |c|
      response = @http.request uri, post
      $log.debug "=>(#{c}/#{@post_retry_max} #{response.code} (#{response.message})"
      # TODO Parse the JSON response from the server
      if response.code == "200"
        # success
        break
      elsif response.code.match(/^40/)
        # user error
        $log.error "#{uri} (#{response.code}): (#{response.message})\n#{response.body}"
        break
      elsif c < @post_retry_max
        # retry
        $log.debug "#{uri} (#{response.code}): Retrying..."
        sleep @post_retry_interval
        next
      else
        # other errors. fluentd will retry processing on exception
        # FIXME: this may duplicate logs when using multiple buffers
        raise "#{uri} (#{response.code}): #{response.message}"
      end  # if response.code
    end  # 1.upto()
  end  # def push_buffer()

end  # class SplunkHTTPEventcollectorOutput

end  # module Fluent
