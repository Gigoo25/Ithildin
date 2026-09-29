import { describe, expect, it } from "bun:test";
import {
  getValidator,
  isRealAwsKey,
  isRealCardNumber,
  isReservedIpv4,
  isReservedIpv6,
  luhn,
  validateChineseID,
  validateCodiceFiscale,
  validateFrenchNIR,
  validateGermanIdNr,
  validateJapanesePhone,
  validateKoreanBRN,
  validateKoreanRRN,
  validateMyNumber,
  validateSpanishNIF,
} from "./validators.ts";

// Specimen numbers from the issuers' own documentation, or bodies made up here
// with the check character computed by an independent implementation. Each is
// also tried with every other check character: exactly one must pass, so a
// validator that accepts anything of the right shape fails.
function onlyCheck(validate: (s: string) => boolean, value: string, alphabet = "0123456789"): void {
  const body = value.slice(0, -1);
  const passing = [...alphabet].filter((c) => validate(body + c));
  expect(passing).toEqual([value.slice(-1)]);
}

describe("checksums", () => {
  it("luhn and card numbers", () => {
    expect(luhn("4111 1111 1111 1111")).toBe(true);
    expect(luhn("4111 1111 1111 1112")).toBe(false);
    expect(luhn("no digits")).toBe(false);
    // Passes Luhn but is a published test card.
    expect(isRealCardNumber("4111111111111111")).toBe(false);
    onlyCheck(luhn, "79927398713");
  });

  it("AWS documentation keys are not real", () => {
    expect(isRealAwsKey("AKIAIOSFODNN7EXAMPLE")).toBe(false);
    expect(isRealAwsKey("AKIAZZZZZZZZZZZZZZZQ")).toBe(true);
  });

  it("Japanese My Number", () => {
    onlyCheck(validateMyNumber, "123456789018");
    expect(validateMyNumber("1234-5678-9018")).toBe(true);
    expect(validateMyNumber("777777777777")).toBe(false);
    expect(validateMyNumber("12345678901")).toBe(false);
  });

  it("French NIR, mainland and Corsica", () => {
    expect(validateFrenchNIR("1 85 12 75 123 456 88")).toBe(true);
    expect(validateFrenchNIR("185127512345689")).toBe(false);
    expect(validateFrenchNIR("269052A00012337")).toBe(true);
    expect(validateFrenchNIR("269052a00012337")).toBe(true);
    expect(validateFrenchNIR("269052B00012364")).toBe(true);
    expect(validateFrenchNIR("269052B00012365")).toBe(false);
    expect(validateFrenchNIR("385127512345688")).toBe(false);
    expect(validateFrenchNIR("18512751234568")).toBe(false);
  });

  it("Italian codice fiscale, with omocodia", () => {
    onlyCheck(validateCodiceFiscale, "RSSMRA85T10A562S", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    expect(validateCodiceFiscale("rssmra85t10a562s")).toBe(true);
    onlyCheck(validateCodiceFiscale, "RSSMRA85T10A56NH", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    // A letter outside the substitution set where a digit belongs.
    expect(validateCodiceFiscale("RSSMRA8AT10A562S")).toBe(false);
    expect(validateCodiceFiscale("RSSMRA85T10A562")).toBe(false);
  });

  it("German Steuer-IdNr", () => {
    onlyCheck(validateGermanIdNr, "86095742719");
    expect(validateGermanIdNr("86 095 742 719")).toBe(true);
    expect(validateGermanIdNr("06095742719")).toBe(false);
  });

  it("Spanish DNI and NIE", () => {
    onlyCheck(validateSpanishNIF, "12345678Z", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    expect(validateSpanishNIF("12345678-z")).toBe(true);
    onlyCheck(validateSpanishNIF, "X1234567L", "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    expect(validateSpanishNIF("Y1234567X")).toBe(validateSpanishNIF("11234567X"));
    expect(validateSpanishNIF("Z1234567R")).toBe(validateSpanishNIF("21234567R"));
    expect(validateSpanishNIF("W1234567L")).toBe(false);
  });

  it("Korean RRN and BRN", () => {
    onlyCheck(validateKoreanRRN, "9001011000006");
    expect(validateKoreanRRN("900101-1000006")).toBe(true);
    expect(validateKoreanRRN("900101100000")).toBe(false);
    onlyCheck(validateKoreanBRN, "1018100340");
    onlyCheck(validateKoreanBRN, "1234567891");
    expect(validateKoreanBRN("123-45-67891")).toBe(true);
    expect(validateKoreanBRN("12345678")).toBe(false);
  });

  it("Chinese resident ID, X check", () => {
    onlyCheck(validateChineseID, "11010519491231002X", "0123456789X");
    expect(validateChineseID("11010519491231002x")).toBe(true);
    expect(validateChineseID("1101051949123100X2")).toBe(false);
  });

  it("Japanese phone numbers", () => {
    expect(validateJapanesePhone("03-1234-5678")).toBe(true);
    expect(validateJapanesePhone("090-1234-5678")).toBe(true);
    expect(validateJapanesePhone("0120-123-456")).toBe(false);
    expect(validateJapanesePhone("0800-123-4567")).toBe(false);
    expect(validateJapanesePhone("01-02-2024")).toBe(false);
    expect(validateJapanesePhone("12-3456-7890")).toBe(false);
  });
});

describe("reserved addresses", () => {
  it("IPv4", () => {
    for (const ip of ["0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.0.1", "192.0.2.1",
      "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.19.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255"]) {
      expect([ip, isReservedIpv4(ip)]).toEqual([ip, true]);
    }
    for (const ip of ["1a.2.3.4", "1.2.3", "1.2.3.4.5", "256.1.1.1"]) expect(isReservedIpv4(ip)).toBe(true);
    for (const ip of ["8.8.8.8", "100.128.0.1", "172.32.0.1", "192.0.1.1", "198.20.0.1"]) expect(isReservedIpv4(ip)).toBe(false);
  });

  it("IPv6, full and compressed", () => {
    for (const ip of ["::", "::1", "0:0:0:0:0:0:0:1", "fe80::1", "FEBF::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1"]) {
      expect([ip, isReservedIpv6(ip)]).toEqual([ip, true]);
    }
    // Malformed: treated as reserved so it is never flagged.
    for (const ip of ["1::2::3", "2001:zz::1", "g::1", "1:2:3:4:5:6:7", "1:2:3:4::5:6:7:8", "1:2:3:4:5:6:7:8:9", "12345::1"]) {
      expect([ip, isReservedIpv6(ip)]).toEqual([ip, true]);
    }
    for (const ip of ["2606:4700::1111", "2a00:1450:4001:0:0:0:0:200e", "::ffff:808:808", "2001:4860::"]) {
      expect([ip, isReservedIpv6(ip)]).toEqual([ip, false]);
    }
  });
});

it("every configured validator name resolves", () => {
  for (const name of ["luhn", "aws-key", "mynumber-jp", "phone-jp", "nir-fr", "codice-fiscale-it", "steuer-id-de", "dni-nie-es",
    "rrn-kr", "brn-kr", "resident-id-cn", "public-ipv4", "public-ipv6"]) {
    expect(typeof getValidator(name)).toBe("function");
  }
  expect(getValidator("public-ipv4")!("8.8.8.8")).toBe(true);
  expect(getValidator("public-ipv6")!("::1")).toBe(false);
  expect(getValidator("no-such")).toBeUndefined();
});
