package burp.vars;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class PostmanFaker {
   private static final Pattern PATTERN = Pattern.compile("\\{\\{\\$([A-Za-z][A-Za-z0-9]*)(?::([A-Za-z]+))?(?:\\(([^)]*)\\))?\\}\\}");
   private static final SecureRandom RNG = new SecureRandom();
   private static final String[] FIRST_NAMES = new String[]{
      "Alice",
      "Bob",
      "Charlie",
      "Diana",
      "Eve",
      "Frank",
      "Grace",
      "Henry",
      "Iris",
      "Jack",
      "Kate",
      "Liam",
      "Mary",
      "Noah",
      "Olivia",
      "Paul",
      "Quinn",
      "Ryan",
      "Sophia",
      "Tom",
      "Uma",
      "Victor",
      "Wendy",
      "Xander",
      "Yara",
      "Zane",
      "Aria",
      "Ben",
      "Chloe",
      "Daniel",
      "Emma",
      "Felix",
      "Gina",
      "Hugo",
      "Isla",
      "James",
      "Kira",
      "Leo",
      "Maya",
      "Nico"
   };
   private static final String[] LAST_NAMES = new String[]{
      "Smith",
      "Johnson",
      "Williams",
      "Jones",
      "Brown",
      "Davis",
      "Miller",
      "Wilson",
      "Moore",
      "Taylor",
      "Anderson",
      "Thomas",
      "Jackson",
      "White",
      "Harris",
      "Martin",
      "Thompson",
      "Garcia",
      "Martinez",
      "Robinson",
      "Clark",
      "Rodriguez",
      "Lewis",
      "Lee",
      "Walker",
      "Hall",
      "Allen",
      "Young",
      "King",
      "Wright",
      "Lopez",
      "Hill",
      "Scott",
      "Green",
      "Adams",
      "Baker",
      "Gonzalez",
      "Nelson",
      "Carter",
      "Mitchell"
   };
   private static final String[] PREFIXES = new String[]{"Mr.", "Mrs.", "Ms.", "Dr.", "Prof."};
   private static final String[] SUFFIXES = new String[]{"Jr.", "Sr.", "II", "III", "PhD", "MD"};
   private static final String[] CITIES = new String[]{
      "Seattle",
      "Portland",
      "Austin",
      "Denver",
      "Boston",
      "Chicago",
      "Atlanta",
      "Miami",
      "Dallas",
      "Phoenix",
      "London",
      "Paris",
      "Berlin",
      "Madrid",
      "Rome",
      "Tokyo",
      "Seoul",
      "Sydney",
      "Toronto",
      "Mumbai"
   };
   private static final String[] STREETS = new String[]{
      "Main",
      "Oak",
      "Maple",
      "Pine",
      "Cedar",
      "Elm",
      "Washington",
      "Lake",
      "Hill",
      "Park",
      "Sunset",
      "Highland",
      "Forest",
      "River",
      "Meadow",
      "Spring",
      "Church",
      "Mill",
      "School",
      "Bridge"
   };
   private static final String[] STREET_SUFFIX = new String[]{"St", "Ave", "Blvd", "Rd", "Ln", "Dr", "Ct", "Way"};
   private static final String[] COUNTRIES = new String[]{
      "United States",
      "United Kingdom",
      "Germany",
      "France",
      "Spain",
      "Italy",
      "Japan",
      "Canada",
      "Australia",
      "Brazil",
      "India",
      "Mexico",
      "Netherlands",
      "Sweden",
      "Norway",
      "Finland",
      "Singapore",
      "South Korea",
      "Ireland",
      "Poland"
   };
   private static final String[] COUNTRY_CODES = new String[]{
      "US", "UK", "DE", "FR", "ES", "IT", "JP", "CA", "AU", "BR", "IN", "MX", "NL", "SE", "NO", "FI", "SG", "KR", "IE", "PL"
   };
   private static final String[] COMPANIES = new String[]{
      "Acme",
      "Globex",
      "Initech",
      "Umbrella",
      "Stark",
      "Wayne",
      "Wonka",
      "Tyrell",
      "Cyberdyne",
      "Hooli",
      "Pied Piper",
      "Massive Dynamic",
      "Soylent",
      "Oscorp",
      "Aperture",
      "Black Mesa",
      "Vault-Tec",
      "Weyland",
      "Yutani",
      "Buy n Large"
   };
   private static final String[] COMPANY_SUFFIX = new String[]{"Inc", "LLC", "Ltd", "Corp", "Co", "GmbH", "Group", "Holdings", "Industries"};
   private static final String[] JOB_TITLES = new String[]{
      "Engineer",
      "Manager",
      "Director",
      "Analyst",
      "Specialist",
      "Architect",
      "Consultant",
      "Coordinator",
      "Designer",
      "Developer",
      "Administrator",
      "Officer",
      "Strategist",
      "Producer",
      "Planner",
      "Technician",
      "Researcher",
      "Auditor",
      "Supervisor",
      "Lead"
   };
   private static final String[] DEPARTMENTS = new String[]{
      "Sales", "Marketing", "Engineering", "HR", "Finance", "Operations", "Legal", "Support", "Research", "Product"
   };
   private static final String[] BS = new String[]{
      "synergize", "leverage", "monetize", "streamline", "optimize", "disrupt", "scale", "automate", "integrate", "incentivize"
   };
   private static final String[] BS_OBJ = new String[]{
      "platforms", "solutions", "ecosystems", "portals", "experiences", "markets", "verticals", "paradigms", "workflows", "networks"
   };
   private static final String[] DOMAINS = new String[]{
      "example.com", "test.org", "demo.io", "sample.net", "mock.dev", "fake.app", "placeholder.co", "stub.tech", "faker.dev", "lorem.ipsum"
   };
   private static final String[] TLDS = new String[]{"com", "org", "net", "io", "co", "app", "dev", "tech", "ai", "cloud"};
   private static final String[] PROTOCOLS = new String[]{"http", "https"};
   private static final String[] HTTP_METHODS = new String[]{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"};
   private static final String[] MIME_TYPES = new String[]{
      "application/json",
      "application/xml",
      "application/octet-stream",
      "application/pdf",
      "text/plain",
      "text/html",
      "text/css",
      "text/csv",
      "image/png",
      "image/jpeg",
      "image/gif",
      "image/webp",
      "audio/mpeg",
      "video/mp4",
      "application/zip",
      "application/javascript"
   };
   private static final String[] FILE_EXTS = new String[]{
      "txt", "pdf", "docx", "xlsx", "png", "jpg", "gif", "mp3", "mp4", "zip", "json", "xml", "html", "css", "js", "csv"
   };
   private static final String[] COLORS = new String[]{
      "red", "blue", "green", "yellow", "purple", "orange", "pink", "black", "white", "gray", "cyan", "magenta"
   };
   private static final String[] CURRENCIES = new String[]{
      "USD", "EUR", "GBP", "JPY", "AUD", "CAD", "CHF", "CNY", "INR", "MXN", "BRL", "KRW", "SGD", "HKD", "NZD", "SEK", "NOK", "DKK", "PLN", "ZAR"
   };
   private static final String[] CURRENCY_SYMBOLS = new String[]{
      "$", "€", "£", "¥", "A$", "C$", "CHF", "¥", "₹", "Mex$", "R$", "₩", "S$", "HK$", "NZ$", "kr", "kr", "kr", "zł", "R"
   };
   private static final String[] CURRENCY_NAMES = new String[]{
      "US Dollar",
      "Euro",
      "British Pound",
      "Japanese Yen",
      "Australian Dollar",
      "Canadian Dollar",
      "Swiss Franc",
      "Chinese Yuan",
      "Indian Rupee",
      "Mexican Peso",
      "Brazilian Real",
      "South Korean Won",
      "Singapore Dollar",
      "Hong Kong Dollar",
      "New Zealand Dollar",
      "Swedish Krona",
      "Norwegian Krone",
      "Danish Krone",
      "Polish Złoty",
      "South African Rand"
   };
   private static final String[] LOCALES = new String[]{"en_US", "en_GB", "es_ES", "fr_FR", "de_DE", "it_IT", "ja_JP", "zh_CN", "pt_BR", "nl_NL"};
   private static final String[] LOREM_WORDS = new String[]{
      "lorem",
      "ipsum",
      "dolor",
      "sit",
      "amet",
      "consectetur",
      "adipiscing",
      "elit",
      "sed",
      "do",
      "eiusmod",
      "tempor",
      "incididunt",
      "ut",
      "labore",
      "et",
      "dolore",
      "magna",
      "aliqua",
      "ad",
      "minim",
      "veniam",
      "quis",
      "nostrud",
      "exercitation",
      "ullamco",
      "laboris",
      "nisi",
      "aliquip",
      "ex"
   };
   private static final String[] PRODUCTS = new String[]{
      "Widget", "Gadget", "Gizmo", "Doohickey", "Thingamajig", "Whatchamacallit", "Apparatus", "Contraption"
   };
   private static final String[] PRODUCT_ADJ = new String[]{
      "Handmade", "Refined", "Sleek", "Ergonomic", "Rustic", "Intelligent", "Awesome", "Practical", "Generic", "Elegant"
   };

   private PostmanFaker() {
   }

   public static String expand(String input) {
      if (input != null && input.indexOf("{{$") >= 0) {
         Matcher m = PATTERN.matcher(input);
         StringBuffer out = new StringBuffer(input.length());

         while (m.find()) {
            String name = m.group(1);
            String modifier = m.group(2);
            String args = m.group(3);
            String value = expandOne(name, modifier, args);
            if (value == null) {
               value = m.group(0);
            }

            m.appendReplacement(out, Matcher.quoteReplacement(value));
         }

         m.appendTail(out);
         return out.toString();
      } else {
         return input;
      }
   }

   private static String expandOne(String name, String modifier, String args) {
      if (name == null) {
         return null;
      } else {
         switch (name.hashCode()) {
            case -1973820663:
               if (name.equals("randomJobDescriptor")) {
                  return pick(new String[]{"Lead", "Senior", "Junior", "Principal", "Staff", "Chief"});
               }

               return null;
            case -1616598382:
               if (name.equals("randomDomainName")) {
                  return pick(DOMAINS);
               }

               return null;
            case -1468417709:
               if (name.equals("randomCountry")) {
                  return pick(COUNTRIES);
               }

               return null;
            case -1446482351:
               if (name.equals("randomStreetName")) {
                  return pick(STREETS) + " " + pick(STREET_SUFFIX);
               }

               return null;
            case -1338327398:
               if (name.equals("randomLoremParagraph")) {
                  StringBuilder sb = new StringBuilder();

                  for (int i = 0; i < 4; i++) {
                     sb.append(capitalize(loremWords(6 + RNG.nextInt(8)))).append(". ");
                  }

                  return sb.toString().trim();
               }

               return null;
            case -1208504800:
               if (name.equals("randomNamePrefix")) {
                  return pick(PREFIXES);
               }

               return null;
            case -1119816993:
               if (name.equals("randomNameSuffix")) {
                  return pick(SUFFIXES);
               }

               return null;
            case -982282114:
               if (name.equals("randomPassword")) {
                  return randomAlphaNumeric(12) + "!";
               }

               return null;
            case -981563342:
               if (name.equals("randomAlphaNumeric")) {
                  return randomAlphaNumeric(10);
               }

               return null;
            case -868415587:
               if (name.equals("randomFullName")) {
                  return pick(FIRST_NAMES) + " " + pick(LAST_NAMES);
               }

               return null;
            case -827563988:
               if (name.equals("randomInt")) {
                  if (args != null) {
                     String[] mm = args.split(",");
                     if (mm.length == 2) {
                        try {
                           int min = Integer.parseInt(mm[0].trim());
                           int max = Integer.parseInt(mm[1].trim());
                           return Integer.toString(min + RNG.nextInt(Math.max(1, max - min + 1)));
                        } catch (NumberFormatException var7) {
                        }
                     }
                  }

                  return Integer.toString(RNG.nextInt(1001));
               }

               return null;
            case -827552340:
               if (name.equals("randomUrl")) {
                  return pick(PROTOCOLS) + "://" + pick(DOMAINS) + "/" + randomAlphaNumeric(6).toLowerCase(Locale.ROOT);
               }

               return null;
            case -822288212:
               if (name.equals("randomCurrencySymbol")) {
                  return pick(CURRENCY_SYMBOLS);
               }

               return null;
            case -760086275:
               if (name.equals("randomLocale")) {
                  return pick(LOCALES);
               }

               return null;
            case -725558176:
               if (name.equals("randomColor")) {
                  return pick(COLORS);
               }

               return null;
            case -723781479:
               if (name.equals("randomEmail")) {
                  return (pick(FIRST_NAMES) + "." + pick(LAST_NAMES) + RNG.nextInt(99) + "@" + pick(DOMAINS)).toLowerCase(Locale.ROOT);
               }

               return null;
            case -722874535:
               if (name.equals("randomFloat")) {
                  return Double.toString(RNG.nextDouble());
               }

               return null;
            case -713466298:
               if (name.equals("randomPrice")) {
                  return String.format(Locale.US, "%d.%02d", RNG.nextInt(1000), RNG.nextInt(100));
               }

               return null;
            case -707082330:
               if (name.equals("randomWords")) {
                  return loremWords(3 + RNG.nextInt(5));
               }

               return null;
            case -620266351:
               if (name.equals("randomCatchPhrase")) {
                  return capitalize(pick(BS)) + " " + pick(BS_OBJ) + " for tomorrow";
               }

               return null;
            case -568599541:
               if (name.equals("randomSemver")) {
                  return RNG.nextInt(10) + "." + RNG.nextInt(20) + "." + RNG.nextInt(100);
               }

               return null;
            case -497431039:
               if (name.equals("randomCurrencyCode")) {
                  return pick(CURRENCIES);
               }

               return null;
            case -497116513:
               if (name.equals("randomCurrencyName")) {
                  return pick(CURRENCY_NAMES);
               }

               return null;
            case -406645053:
               if (name.equals("randomDatePast")) {
                  return formatDate(System.currentTimeMillis() - (long)(RNG.nextDouble() * 5.0 * 365.0 * 24.0 * 3600.0 * 1000.0));
               }

               return null;
            case -211658700:
               if (name.equals("randomDateFuture")) {
                  return formatDate(System.currentTimeMillis() + (long)(RNG.nextDouble() * 5.0 * 365.0 * 24.0 * 3600.0 * 1000.0));
               }

               return null;
            case -183090036:
               if (name.equals("randomHTTPMethod")) {
                  return pick(HTTP_METHODS);
               }

               return null;
            case -154802345:
               if (name.equals("randomProductName")) {
                  return pick(PRODUCT_ADJ) + " " + pick(PRODUCTS);
               }

               return null;
            case -140052000:
               if (name.equals("randomCountryCode")) {
                  return pick(COUNTRY_CODES);
               }

               return null;
            case 3184265:
               if (!name.equals("guid")) {
                  return null;
               }
               break;
            case 55126294:
               if (name.equals("timestamp")) {
                  return Long.toString(System.currentTimeMillis() / 1000L);
               }

               return null;
            case 115136718:
               if (name.equals("randomCity")) {
                  return pick(CITIES);
               }

               return null;
            case 115291432:
               if (name.equals("randomIPv4")) {
                  return RNG.nextInt(256) + "." + RNG.nextInt(256) + "." + RNG.nextInt(256) + "." + RNG.nextInt(256);
               }

               return null;
            case 115291434:
               if (name.equals("randomIPv6")) {
                  StringBuilder sb = new StringBuilder();

                  for (int i = 0; i < 8; i++) {
                     if (i > 0) {
                        sb.append(':');
                     }

                     sb.append(String.format("%04x", RNG.nextInt(65536)));
                  }

                  return sb.toString();
               }

               return null;
            case 115529700:
               if (name.equals("randomPort")) {
                  return Integer.toString(1024 + RNG.nextInt(64511));
               }

               return null;
            case 115652350:
               if (!name.equals("randomUUID")) {
                  return null;
               }
               break;
            case 115738221:
               if (name.equals("randomWord")) {
                  return pick(LOREM_WORDS);
               }

               return null;
            case 116592844:
               if (name.equals("randomDateRecent")) {
                  return formatDate(System.currentTimeMillis() - RNG.nextInt(604800000));
               }

               return null;
            case 144045460:
               if (name.equals("randomPhoneNumber")) {
                  return String.format("(%03d) %03d-%04d", RNG.nextInt(900) + 100, RNG.nextInt(900) + 100, RNG.nextInt(10000));
               }

               return null;
            case 250398836:
               if (name.equals("randomBs")) {
                  return pick(BS) + " " + pick(BS_OBJ);
               }

               return null;
            case 430250919:
               if (name.equals("randomJobArea")) {
                  return pick(DEPARTMENTS);
               }

               return null;
            case 430824020:
               if (name.equals("randomJobType")) {
                  return pick(new String[]{"Full-time", "Part-time", "Contract", "Temporary", "Intern"});
               }

               return null;
            case 470170238:
               if (name.equals("randomJobTitle")) {
                  return pick(JOB_TITLES);
               }

               return null;
            case 475671669:
               if (name.equals("randomDepartment")) {
                  return pick(DEPARTMENTS);
               }

               return null;
            case 636099620:
               if (name.equals("randomLastName")) {
                  return pick(LAST_NAMES);
               }

               return null;
            case 655721039:
               if (name.equals("randomLatitude")) {
                  return String.format(Locale.US, "%.6f", (RNG.nextDouble() - 0.5) * 180.0);
               }

               return null;
            case 675008472:
               if (name.equals("randomFirstName")) {
                  return pick(FIRST_NAMES);
               }

               return null;
            case 676579950:
               if (name.equals("randomStreetAddress")) {
                  return RNG.nextInt(9999) + 1 + " " + pick(STREETS) + " " + pick(STREET_SUFFIX);
               }

               return null;
            case 679538732:
               if (name.equals("randomLongitude")) {
                  return String.format(Locale.US, "%.6f", (RNG.nextDouble() - 0.5) * 360.0);
               }

               return null;
            case 703578993:
               if (name.equals("randomMimeType")) {
                  return pick(MIME_TYPES);
               }

               return null;
            case 828432357:
               if (name.equals("randomCompanyName")) {
                  return pick(COMPANIES) + " " + pick(COMPANY_SUFFIX);
               }

               return null;
            case 853603447:
               if (name.equals("randomUserAgent")) {
                  return "Mozilla/5.0 (BurpMan/" + RNG.nextInt(99) + "; +https://github.com/JohnRiocelCenon/BurpMan)";
               }

               return null;
            case 1013693634:
               if (name.equals("randomFileExt")) {
                  return pick(FILE_EXTS);
               }

               return null;
            case 1018137527:
               if (name.equals("randomLoremSentence")) {
                  return capitalize(loremWords(6 + RNG.nextInt(8))) + ".";
               }

               return null;
            case 1106535547:
               if (name.equals("randomProtocol")) {
                  return pick(PROTOCOLS);
               }

               return null;
            case 1359977482:
               if (name.equals("randomFileName")) {
                  return randomAlphaNumeric(8).toLowerCase(Locale.ROOT) + "." + pick(FILE_EXTS);
               }

               return null;
            case 1360179385:
               if (name.equals("randomFileType")) {
                  return pick(new String[]{"image", "video", "audio", "application", "text"});
               }

               return null;
            case 1388528024:
               if (name.equals("randomDomainSuffix")) {
                  return pick(TLDS);
               }

               return null;
            case 1497492380:
               if (name.equals("randomLoremSentences")) {
                  return capitalize(loremWords(6 + RNG.nextInt(8))) + ". " + capitalize(loremWords(6 + RNG.nextInt(8))) + ".";
               }

               return null;
            case 1559244460:
               if (name.equals("randomProduct")) {
                  return pick(PRODUCT_ADJ) + " " + pick(PRODUCTS);
               }

               return null;
            case 1586618987:
               if (name.equals("randomZipCode")) {
                  return String.format("%05d", RNG.nextInt(100000));
               }

               return null;
            case 1608727275:
               if (name.equals("randomHexColor")) {
                  return "#" + String.format("%06x", RNG.nextInt(16777216));
               }

               return null;
            case 1709420744:
               if (name.equals("randomMacAddress")) {
                  StringBuilder sb = new StringBuilder();

                  for (int i = 0; i < 6; i++) {
                     if (i > 0) {
                        sb.append(':');
                     }

                     sb.append(String.format("%02x", RNG.nextInt(256)));
                  }

                  return sb.toString();
               }

               return null;
            case 1715957291:
               if (name.equals("randomCompanySuffix")) {
                  return pick(COMPANY_SUFFIX);
               }

               return null;
            case 1765571850:
               if (name.equals("randomNameTitle")) {
                  return pick(PREFIXES);
               }

               return null;
            case 1829032665:
               if (name.equals("randomUserName")) {
                  return (pick(FIRST_NAMES) + "." + pick(LAST_NAMES) + RNG.nextInt(99)).toLowerCase(Locale.ROOT);
               }

               return null;
            case 1898739217:
               if (name.equals("isoTimestamp")) {
                  SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
                  f.setTimeZone(TimeZone.getTimeZone("UTC"));
                  return f.format(new Date());
               }

               return null;
            case 1933430245:
               if (name.equals("randomBoolean")) {
                  return Boolean.toString(RNG.nextBoolean());
               }

               return null;
            default:
               return null;
         }

         String uuid = UUID.randomUUID().toString();
         return "upper".equalsIgnoreCase(modifier) ? uuid.toUpperCase(Locale.ROOT) : uuid;
      }
   }

   private static String pick(String[] arr) {
      return arr[RNG.nextInt(arr.length)];
   }

   private static String loremWords(int count) {
      StringBuilder sb = new StringBuilder();

      for (int i = 0; i < count; i++) {
         if (i > 0) {
            sb.append(' ');
         }

         sb.append(pick(LOREM_WORDS));
      }

      return sb.toString();
   }

   private static String capitalize(String s) {
      return s != null && !s.isEmpty() ? Character.toUpperCase(s.charAt(0)) + s.substring(1) : s;
   }

   private static String randomAlphaNumeric(int len) {
      String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      StringBuilder sb = new StringBuilder(len);

      for (int i = 0; i < len; i++) {
         sb.append(alphabet.charAt(RNG.nextInt(alphabet.length())));
      }

      return sb.toString();
   }

   private static String formatDate(long epochMs) {
      SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
      f.setTimeZone(TimeZone.getTimeZone("UTC"));
      return f.format(new Date(epochMs));
   }
}
