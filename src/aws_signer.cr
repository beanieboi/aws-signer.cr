require "openssl"
require "openssl/hmac"
require "time"
require "uri"
require "http"

require "./aws_signer/*"

module AwsSigner
  RFC8601BASIC  = "%Y%m%dT%H%M%SZ"
  DATE_PATTERNS = {"%a, %d %b %Y %H:%M:%S %z", "%A, %d-%b-%y %H:%M:%S %z", "%a %b %e %H:%M:%S %Y", "%FT%H:%M:%S%:z"}

  def self.configure
    @@configuration = Config.new
    yield config
  end

  def self.config
    @@configuration ||= Config.new
  end

  def self.sign(service : String, method : String, uri : URI, headers : Hash(String, String), body : String) : Hash(String, String)
    method = method.upcase

    headers_array = headers.to_a
    sorted_headers = headers_array.sort_by { |header| header[0] }
    headers_keys = sorted_headers.map { |header| header[0].downcase }.join(";")

    headers_key_value = sorted_headers.map do |header|
      header = header.to_a
      [header[0].downcase, header[1].strip].join(":")
    end.join("\n") + "\n"

    host = uri.host.as(String)

    date_header = headers["Date"]? || headers["DATE"]? || headers["date"]?
    date_to_parse = date_header ? parse_time(date_header) : Time.now.to_utc

    begin
      date_to_parse = date_to_parse.as(Time)
    rescue ex : TypeCastError
    end

    date_to_parse ||= Time.now

    date = date_to_parse.to_s(RFC8601BASIC)

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
    k_region = hmac(k_date, config.region)
    k_service = hmac(k_region, service)
    k_credentials = hmac(k_service, "aws4_request")
    signature = hexhmac(k_credentials, string_to_sign)

    authorization = [
      "AWS4-HMAC-SHA256 Credential=#{config.access_key}/#{credential_string}",
      "SignedHeaders=#{headers_keys}",
      "Signature=#{signature}",
    ].join(", ")

    signed = headers.dup
    signed["Authorization"] = authorization
    signed
  end

  def self.parse_time(time_str : String) : Time?
    DATE_PATTERNS.each do |pattern|
      begin
        return Time.parse(time_str, pattern, kind: Time::Kind::Utc)
      rescue Time::Format::Error
      end
    end

    nil
  end

  def self.hexdigest(value)
    OpenSSL::Digest.new("sha256").update(value).hexdigest
  end

  def self.hmac(key, value)
    OpenSSL::HMAC.digest(:sha256, key, value)
  end

  def self.hexhmac(key, value)
    OpenSSL::HMAC.hexdigest(:sha256, key, value)
  end
end
