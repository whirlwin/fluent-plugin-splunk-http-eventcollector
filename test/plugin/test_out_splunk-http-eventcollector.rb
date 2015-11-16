require 'helper'

class SplunkHTTPEventcollectorOutputTest < Test::Unit::TestCase
  def setup
    Fluent::Test.setup
  end

  CONFIG = %[
    server localhost:8089
    verify false
    token changeme
  ]

  def create_driver(conf=CONFIG, tag='test')
    Fluent::Test::BufferedOutputTestDriver.new(Fluent::SplunkHTTPEventcollectorOutput, tag).configure(conf)
  end

  def test_configure
    # default
    d = create_driver
    assert_equal '{TAG}', d.instance.source
    assert_equal '_json', d.instance.sourcetype
  end

  def test_write
    d = create_driver

    time = Time.parse("2010-01-02 13:14:15 UTC").to_i
    d.emit({"a"=>1}, time)
    d.emit({"a"=>2}, time)

    d.run
  end
end
