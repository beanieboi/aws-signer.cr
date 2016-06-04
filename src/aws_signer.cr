require "openssl"
require "openssl/hmac"
require "time"
require "uri"
require "http"

require "./aws_signer/*"

module AwsSigner
  RFC8601BASIC = "%Y%m%dT%H%M%SZ"

  def self.configure
    @@configuration = Config.new
    yield config
  end

  def self.config
    @@configuration ||= Config.new
  end

  def self.sign(method : String, uri : URI, headers : Hash(String, String), body : String) : Hash(String, String)
    method = method.upcase

    headers_array = headers.to_a

    sorted_headers = headers_array.sort_by { |k| k[0] }
    headers_keys = sorted_headers.map { |k, _v| k[0].downcase }.join(";")
    headers_key_value = sorted_headers.map { |k, _v| [k[0].downcase, k[1].strip].join(":") }.join("\n") + "\n"

    host = uri.host.as(String)
    service = host.split(".", 2)[0]

    date_header = headers["Date"]? || headers["DATE"]? || headers["date"]?
    date_to_parse = date_header ? HTTP.parse_time(date_header) : Time.now
    date_to_parse = date_to_parse.as(Time)
    date = date_to_parse.to_utc.to_s(RFC8601BASIC)

    canonical_request =
      [
        method,
        uri.path,
        uri.query,
        headers_key_value,
        headers_keys,
        hexdigest(body || ""),
      ].join("\n")

    credential_string =
      [
        date[0, 8],
        config.region,
        service,
        "aws4_request",
      ].join("/")

    string_to_sign =
      [
        "AWS4-HMAC-SHA256",
        date,
        credential_string,
        hexdigest(canonical_request),
      ].join("\n")

    k_date = hmac("AWS4" + config.secret_key, date[0, 8])
    p "k_date #{k_date}"
    k_region = hmac(k_date, config.region)
    p "k_region #{k_region}"
    k_service = hmac(k_region, service)
    p "k_service #{k_service}"
    k_credentials = hmac(k_service, "aws4_request")
    p "k_credentials #{k_credentials}"
    signature = hexhmac(k_credentials, string_to_sign)

    if true
      puts "<string to sign>"
      puts string_to_sign
      puts "</string to sign>"
      puts "<canonical_request>"
      puts canonical_request
      puts "</canonical_request>"
      puts "authorization"
    end

    authorization = [
      "AWS4-HMAC-SHA256 Credential=#{config.access_key}/#{credential_string}",
      "SignedHeaders=#{headers_keys}",
      "Signature=#{signature}",
    ].join(", ")

    signed = headers.dup
    signed["Authorization"] = authorization
    signed
  end

  def self.hexdigest(value)
    OpenSSL::Digest.new("sha256").update(value).hexdigest
  end

  def self.hmac(key, value)
    # p "key:#{key}"
    # p "val:#{value}"

    OpenSSL::HMAC.digest(:sha256, key, value)
  end

  def self.hexhmac(key, value)
    OpenSSL::HMAC.hexdigest(:sha256, key, value)
  end
end
