import type { RuleConfig } from "./rules.ts";

// Labelled values need their own rules: broad numeric/date detection would
// hide release dates, counts and ordinary identifiers throughout source code.
const YEAR = String.raw`(?:18|19|20)\d{2}`;
const MONTH = String.raw`(?:0?[1-9]|1[0-2])`;
const DAY = String.raw`(?:0?[1-9]|[12]\d|3[01])`;
const MONTH_NAME =
  "(?:jan(?:uary|vier|uar)?|gennaio|enero|feb(?:ruary|ruar|braio|rero)?|février|" +
  "mar(?:ch|zo|s)?|märz|maerz|apr(?:il|ile)?|avril|abril|may|mai|mayo|maggio|" +
  "jun(?:e|i|io)?|juin|giugno|" +
  "jul(?:y|i|io)?|juillet|luglio|aug(?:ust)?|août|agosto|sep(?:tember|tiembre)?|" +
  "septembre|settembre|setiembre|oct(?:ober|ubre)?|octobre|oktober|ottobre|nov(?:ember|iembre)?|" +
  "novembre|dec(?:ember)?|décembre|dezember|dicembre|diciembre)";
const DATE =
  `${YEAR}[-/.]${MONTH}[-/.]${DAY}|${DAY}[-/.]${MONTH}[-/.]${YEAR}|` +
  `${MONTH}[-/.]${DAY}[-/.]${YEAR}|` +
  `${YEAR}年[ \t]*${MONTH}月[ \t]*${DAY}日|` +
  `${YEAR}년[ \t]*${MONTH}월[ \t]*${DAY}일|` +
  `${DAY}\\.?[ \\t]+(?:de[ \\t]+)?${MONTH_NAME}[ \\t]+(?:de[ \\t]+)?${YEAR}|` +
  `${MONTH_NAME}[ \\t]+${DAY},?[ \\t]+${YEAR}`;
const DOB_LABEL =
  "d\\.?o\\.?b\\.?|date[ _-]*of[ _-]*birth|birth[ _-]*date|" +
  "生年月日|誕生日|出生日期|出生年月日|生日|생년월일|생일|" +
  "date[ \\t]+de[ \\t]+naissance|data[ \\t]+di[ \\t]+nascita|" +
  "geburtsdatum|fecha[ \\t]+de[ \\t]+nacimiento";
const CUSTOMER_LABEL =
  "(?:customer|member(?:ship)?)[ _-]*(?:id|number|no\\.?|#)|" +
  "account[ _-]*(?:number|no\\.?|#)|(?:会員|顧客|お客様)(?:番号|ID|No\\.?)|口座番号|" +
  "(?:客户|客戶|会员|會員|账户|帳戶)(?:编号|編號|号码|號碼|号|號|ID)|" +
  "(?:고객|회원|계좌)[ \\t]*(?:번호|ID)|" +
  "numéro[ \\t]+(?:de[ \\t]+)?(?:client|membre|compte)|" +
  "numero[ \\t]+(?:cliente|socio|conto)|(?:kunden|mitglieds|konto)nummer|" +
  "número[ \\t]+(?:de[ \\t]+)?(?:cliente|socio|cuenta)";
const VALUE_SEPARATOR = String.raw`["']?[ \t]*(?::|：|=|#|は|is\b|was\b)?[ \t]*["'「]?`;
const TOKEN_END = String.raw`(?![\p{L}\p{N}_-])`;
const WORD = String.raw`[\p{L}][\p{L}'’.-]{0,29}`;
const STREET_NAME = `${WORD}(?:[ \\t]+${WORD}){0,5}`;
const CITY = String.raw`\p{Lu}[\p{L}'’-]{1,29}(?:[ \t]+\p{Lu}[\p{L}'’-]{1,29}){0,3}`;
const POSTAL_CITY = String.raw`[ \t]*,?[ \t]+\d{5}[ \t]+` + CITY;
const EURO_START = String.raw`(?<![\p{L}\p{N}/.-])`;
const JAPAN =
  "北海道|東京都|(?:京都|大阪)府|" +
  "(?:青森|岩手|宮城|秋田|山形|福島|茨城|栃木|群馬|埼玉|千葉|神奈川|新潟|富山|" +
  "石川|福井|山梨|長野|岐阜|静岡|愛知|三重|滋賀|兵庫|奈良|和歌山|鳥取|島根|岡山|" +
  "広島|山口|徳島|香川|愛媛|高知|福岡|佐賀|長崎|熊本|大分|宮崎|鹿児島|沖縄)県";
const JP_NAME = String.raw`[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}々ー]`;
const CHINA =
  "北京|天津|上海|重庆|河北|河南|山西|山东|辽宁|吉林|黑龙江|江苏|江西|浙江|安徽|" +
  "福建|湖北|湖南|广东|广西|海南|四川|贵州|云南|陕西|甘肃|青海|台湾|内蒙古|西藏|" +
  "宁夏|新疆|香港|澳门";
const KOREA =
  "서울(?:특별시|시)?|(?:부산|대구|인천|광주|대전|울산)(?:광역시|시)?|" +
  "세종(?:특별자치시|시)?|경기도?|강원(?:특별자치도|도)?|충청[남북]도|충[남북]|" +
  "전라[남북]도|전[남북](?:특별자치도)?|경상[남북]도|경[남북]|제주(?:특별자치도|도)?";

// Quote capture and backreference make spaces part of a quoted password, but
// stop an unquoted value at its first separator. Capture 2 is the value alone.
const PASSWORD_VALUE = String.raw`(["']?)([^\r\n"'\x60]{1,256}?)\1(?=$|[ \t\r\n,;)}\]])`;
// A key that names a credential, at the end of the name: `ClientSecret`, `db_password`,
// `X-Auth-Token`, `secret_key_base`. `max_tokens` and `token_type` do not end in one.
const CREDENTIAL_KEY =
  String.raw`[A-Za-z0-9_.-]{0,40}?(?:secret[_-]key[_-]base|secret|token|api[_-]?key|` +
  String.raw`passw(?:or)?d)`;
const AWS_ID =
  String.raw`(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|APKA|ASCA|AGPA|AIDA|AROA|` +
  String.raw`AIPA|ANPA|ANVA|ASIA)`;

export const CONTEXT_RULES: RuleConfig[] = [
  {
    id: "pii-date-of-birth",
    description: "Date of birth after a localized birth-date label",
    regex:
      `(?<![\\p{L}\\p{N}_])(?:${DOB_LABEL})(?:(?![\\p{L}\\p{N}_])|(?=は))` +
      `${VALUE_SEPARATOR}(${DATE})(?![\\p{L}\\p{N}/.-])`,
    flags: "giu",
    secretGroup: 1,
    category: "pii",
  },
  {
    id: "pii-customer-number",
    description: "Customer, member or account identifier after a localized label",
    regex:
      `(?<![\\p{L}\\p{N}_])(?:${CUSTOMER_LABEL})(?:(?![\\p{L}\\p{N}_])|(?=は))` +
      `${VALUE_SEPARATOR}([A-Z0-9Ａ-Ｚａ-ｚ０-９][A-Z0-9Ａ-Ｚａ-ｚ０-９_-]{2,30}` +
      `[A-Z0-9Ａ-Ｚａ-ｚ０-９])${TOKEN_END}`,
    flags: "giu",
    secretGroup: 1,
    validate: "customer-number",
    category: "pii",
  },
  {
    id: "pii-address-jp",
    description: "Japanese prefecture, municipality and numbered block",
    regex:
      `(?:${JAPAN})(?=${JP_NAME}{1,24}[市区郡町村])${JP_NAME}{2,40}(?<![のはをがにでとへも])` +
      String.raw`[0-9０-９]{1,4}(?:丁目|[-－])[0-9０-９]{1,4}` +
      String.raw`(?:(?:番地?|[-－])[0-9０-９]{1,4})?号?`,
    flags: "gu",
    category: "pii",
  },
  {
    id: "pii-address-cn",
    description: "Chinese region, street and numbered building",
    regex:
      `(?:${CHINA})(?:省|市|(?:壮族|回族|维吾尔)?自治区|特别行政区)?` +
      String.raw`[\p{Script=Han}]{2,40}(?:路|街|道|巷|弄)[0-9０-９]{1,5}[号號]`,
    flags: "gu",
    category: "pii",
  },
  {
    id: "pii-address-kr",
    description: "Korean region, road or lot name and building number",
    regex:
      `(?<![가-힣])(?:${KOREA})[ \\t]+` +
      String.raw`(?:[가-힣]{1,12}[시군구읍면][ \t]+){0,3}` +
      String.raw`[가-힣0-9·]{1,32}[로길동리][ \t]+\d{1,5}(?:-\d{1,5})?(?![\d-])`,
    flags: "gu",
    category: "pii",
  },
  {
    id: "pii-address-fr",
    description: "French street address with postal code and town",
    regex:
      `${EURO_START}\\d{1,4}(?:[ \\t]?(?:bis|ter))?[ \\t]+` +
      `(?:[Rr]ue|[Aa]venue|[Bb]oulevard|[Aa]llée|[Cc]hemin|[Pp]lace|[Ii]mpasse)` +
      `[ \\t]+${STREET_NAME}${POSTAL_CITY}`,
    flags: "gu",
    category: "pii",
  },
  {
    id: "pii-address-it",
    description: "Italian street address with civic number, postal code and town",
    regex:
      `${EURO_START}(?:[Vv]ia|[Vv]iale|[Pp]iazza|[Cc]orso|[Vv]icolo|[Ll]ar\\x67o)` +
      `[ \\t]+${STREET_NAME},?[ \\t]+\\d{1,4}[A-Za-z]?${POSTAL_CITY}`,
    flags: "gu",
    category: "pii",
  },
  {
    id: "pii-address-de",
    description: "German street address with house number, postal code and town",
    regex:
      `${EURO_START}\\p{Lu}[\\p{L}'’-]{1,40}` +
      `(?:straße|strasse|Straße|Strasse|weg|Weg|platz|Platz|allee|Allee|gasse|Gasse)` +
      `[ \\t]+\\d{1,4}[a-z]?${POSTAL_CITY}`,
    flags: "gu",
    category: "pii",
  },
  {
    id: "pii-address-es",
    description: "Spanish street address with number, postal code and town",
    regex:
      `${EURO_START}(?:[Cc]alle|[Aa]venida|[Pp]laza|[Pp]aseo|[Cc]amino|[Cc]arretera)` +
      `[ \\t]+${STREET_NAME},?[ \\t]+\\d{1,4}[A-Za-z]?${POSTAL_CITY}`,
    flags: "gu",
    category: "pii",
  },
  {
    id: "pii-nino-uk",
    description: "UK National Insurance number, compact or spaced",
    regex: String.raw`\b[A-Z]{2}[ \t]?\d{2}[ \t]?\d{2}[ \t]?\d{2}[ \t]?[A-D]\b`,
    validate: "nino-uk",
    category: "pii",
  },
  {
    id: "docker-hub-pat",
    description: "Docker Hub personal access token",
    regex: String.raw`(?<![A-Za-z0-9_])dckr_pat_[A-Za-z0-9_-]{27,256}(?![A-Za-z0-9_-])`,
    category: "secret",
  },
  {
    id: "aws-secret-near-key-id",
    description: "AWS secret access key beside a non-example access-key ID",
    regex:
      `(?<![A-Za-z0-9])${AWS_ID}(?![A-Z0-9]{9}EXAMPLE)[A-Z0-9]{16}` +
      String.raw`(?![A-Za-z0-9])[^\r\n]{0,80}?(?:\r?\n[^\r\n]{0,80}?)?` +
      String.raw`(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])`,
    secretGroup: 1,
    entropyThreshold: 4,
    validate: "aws-secret-shape",
    category: "secret",
  },
  {
    id: "password-json-key",
    description: "Literal password in a JSON password or pwd field",
    regex:
      String.raw`"(?:[A-Za-z0-9._-]{1,64}[._-]|[a-z][A-Za-z0-9]{0,63}(?=[A-Z]))?` +
      String.raw`(?:[Pp]ass(?:word|wd)?|[Pp]wd|PASS(?:WORD|WD)?|PWD)"[ \t]*:[ \t]*` +
      String.raw`"([^"\r\n]{1,256})"`,
    flags: "g",
    secretGroup: 1,
    validate: "literal-password",
    category: "secret",
  },
  {
    id: "password-assignment",
    description: "Literal password assigned to an explicitly named password field",
    regex:
      String.raw`(?<![\w.-])(?:[a-z0-9]+[_-]){0,3}(?:password|passwd|pwd)` +
      String.raw`[ \t]*[:=][ \t]*` +
      PASSWORD_VALUE,
    flags: "gim",
    secretGroup: 2,
    validate: "literal-password",
    category: "secret",
  },
  {
    id: "password-cli-flag",
    description: "Literal password supplied to a long command-line flag",
    regex: String.raw`(?<![\w-])--(?:password|passwd|pass|pwd)(?:=|[ \t]+)` + PASSWORD_VALUE,
    flags: "gi",
    secretGroup: 2,
    validate: "literal-password",
    category: "secret",
  },
  {
    id: "mysql-password",
    description: "Quoted password on the mysql or mariadb short password flag",
    regex:
      String.raw`\b(?:mysql|mariadb)(?:[ \t]+[^\s;|&]{1,128}){0,16}?[ \t]+-p` +
      String.raw`(?=["'])` +
      PASSWORD_VALUE,
    secretGroup: 2,
    validate: "literal-password",
    category: "secret",
  },
  {
    id: "password-netrc",
    description: "Literal password in a netrc password field",
    regex:
      String.raw`(?:^|\n)[ \t]*(?:machine[ \t]+[^\r\n]{1,256}?[ \t])?password[ \t]+` +
      PASSWORD_VALUE +
      String.raw`(?=[ \t]*(?:#|\r?$))`,
    flags: "gim",
    secretGroup: 2,
    validate: "literal-password",
    category: "secret",
  },
  {
    id: "password-prose-short",
    description: "Short mixed password in English or Japanese prose",
    regex:
      String.raw`(?:\b(?:password|passwd|pwd|pw)[ \t]+(?:is|was|to)[ \t]+|` +
      String.raw`パスワード(?:は[ \t]*|[ \t]*[：:][ \t]*))["'「]?` +
      String.raw`((?:(?!です|である)[^\s"'」\x60。、]){4,128}(?<![.,;:?)\]}]))`,
    flags: "giu",
    secretGroup: 1,
    validate: "prose-password",
    category: "secret",
  },
  {
    id: "redis-auth",
    description: "Literal Redis AUTH password or redis-cli -a argument",
    regex:
      String.raw`(?:^AUTH[ \t]+(?:[^\s"']{1,64}[ \t]+` +
      String.raw`(?=(?:"[^"\r\n]+"|'[^'\r\n]+'|[^\s"']+)[ \t]*\r?$))?|` +
      String.raw`\bredis-cli(?:[ \t]+[^\s;|&]{1,128}){0,16}?[ \t]+-a[ \t]+)` +
      PASSWORD_VALUE,
    flags: "gm",
    secretGroup: 2,
    validate: "literal-password",
    category: "secret",
  },
  // A quoted literal on a credential-named key, in the separators code and config
  // use for one: `=`, `:`, PHP's `=>`, and a key closed by a quote or `]`. The
  // entropy rules need twenty characters, so a six-digit token or a hyphenated
  // passphrase went out under every one of these keys (V23 holdout, needle
  // experiment). Quoted only: an unquoted value there is usually a variable.
  {
    id: "credential-quoted-assignment",
    description: "Quoted literal assigned to a credential-named key",
    regex:
      String.raw`(?<![\w.$-])` +
      CREDENTIAL_KEY +
      String.raw`["']?\]?[ \t]*(?::|=>|=)[ \t]*(["'])([^"'\r\n]{1,256})\1`,
    flags: "gi",
    secretGroup: 2,
    validate: "literal-credential",
    category: "secret",
  },
  // The same in a dotenv or shell line, unquoted. Upper-case keys only, the
  // spelling of an environment variable rather than of code, and `=` with no
  // space around it, as dotenv and shell write it: `KEY = cfg.x` is Nix and
  // `KEY = 0x4` is a Go constant. A dotted value is an attribute path.
  {
    id: "credential-env-line",
    description: "Unquoted literal on an upper-case credential environment variable",
    regex:
      String.raw`^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|API_?KEY|PASSWORD)` +
      String.raw`=([^\s"'#$\x60;.]{4,256})(?=[ \t]*(?:#|\r?$))`,
    flags: "gm",
    secretGroup: 1,
    validate: "literal-credential",
    category: "secret",
  },
  // `<password>…</password>` and .NET's `<add key="ApiSecret" value="…" />`.
  {
    id: "credential-xml-element",
    description: "Literal in an XML element named for a credential",
    regex:
      String.raw`<((?:[\w.-]+:)?[A-Za-z_]*(?:password|passwd|secret|token|api-?key|api_key))>` +
      String.raw`([^<>\s]{1,256})</\1>`,
    flags: "gi",
    secretGroup: 2,
    validate: "literal-credential",
    category: "secret",
  },
  {
    id: "credential-xml-setting",
    description: "Literal value of an XML setting keyed by a credential name",
    regex:
      String.raw`\bkey=(["'])[\w.:-]*(?:password|passwd|secret|token|api-?key|api_key)\1` +
      String.raw`[ \t]+value=(["'])([^"'\r\n]{1,256})\2`,
    flags: "gi",
    secretGroup: 3,
    validate: "literal-credential",
    category: "secret",
  },
  {
    id: "powershell-plaintext-securestring",
    description: "Literal passed to ConvertTo-SecureString -AsPlainText",
    regex:
      String.raw`\bConvertTo-SecureString[ \t]+(?:-String[ \t]+)?(["'])([^"'\r\n]{1,256})\1` +
      String.raw`[ \t]+-AsPlainText`,
    flags: "gi",
    secretGroup: 2,
    validate: "literal-password",
    category: "secret",
  },
  {
    id: "pii-phone-intl",
    description: "International phone number with a leading country code and separators",
    regex:
      String.raw`(?<![\w+])\+[1-9]\d{0,2}(?:[ .-]?\d|[ \t]?\(\d{1,4}\)){5,14}` +
      String.raw`(?![\d(]|[ .-]\d)`,
    validate: "phone-intl",
    category: "pii",
  },
];
