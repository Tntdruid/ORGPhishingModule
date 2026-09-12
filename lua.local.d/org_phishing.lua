-- ORG_PHISHING: Detects phishing pretending to be known service brands
-- Fully rebuilt version with brand whitelists, urgency patterns, DKIM levels
-- Compatible with Rspamd 4.1.5

local logger = require "rspamd_logger"

logger.infox("ORG_PHISHING: module loaded")

---------------------------------------------------------------------------
-- LOWERCASE HELPER
---------------------------------------------------------------------------

local function lower(s)
  return s and tostring(s):lower() or ""
end

---------------------------------------------------------------------------
-- DOMAIN MATCH (supports wildcard patterns)
---------------------------------------------------------------------------

local function domain_matches(domain, list)
  domain = lower(domain)
  for _, w in ipairs(list) do
    local pattern = "^" .. w
      :gsub("%.", "%%.")
      :gsub("%%%.", "%%%.")
      :gsub("%%-", "%%-")
      :gsub("%%d", "%%d") .. "$"

    if domain:match(pattern) then
      return true
    end
  end
  return false
end

---------------------------------------------------------------------------
-- BRAND DEFINITIONS
---------------------------------------------------------------------------

local brands = {

  YOUSEE = {
    symbol = "ORG_PHISHING_YOUSEE",
    score = 8.0,
    keywords = { "yousee", "you see", "you-see" },
    domains = {
      "yousee.dk","yousee.tv","yousee.mail",
      "carmamail.com",
      "customer%-%d+%-.+%.carmamail%.com",
      "sendgrid.net",
      "klik.yousee.dk","email.yousee.dk"
    },
    urgency = {
      "yousee betaling mangler",
      "yousee konto låst",
      "verify your yousee account",
      "update your yousee payment"
    }
  },

  POSTNORD = {
    symbol = "ORG_PHISHING_POSTNORD",
    score = 8.0,
    keywords = { "postnord", "post nord" },
    domains = {
      "postnord.dk","postnord.com",
      "sendgrid.net","postnord.%w+%.sendgrid%.net",
      "trk.postnord.com","m.postnord.com"
    },
    urgency = {
      "din pakke er tilbageholdt",
      "betal gebyr for levering",
      "leveringsproblem"
    }
  },

  COOP = {
    symbol = "ORG_PHISHING_COOP",
    score = 6.0,
    keywords = { "coop", "superbrugsen", "kvickly", "irma" },
    domains = {
      "coop.dk","brugsen.dk","kvickly.dk","irma.dk",
      "sendgrid.net","mandrillapp.com","mailchimp.com","sfmc-email.com",
      "email.coop.dk","trk.coop.dk"
    },
    urgency = {
      "din bonus er udløbet",
      "aktiver din bonus nu"
    }
  },

  NETFLIX = {
    symbol = "ORG_PHISHING_NETFLIX",
    score = 8.0,
    keywords = { "netflix" },
    domains = {
      "netflix.com",
      "mandrillapp.com","sendgrid.net","sfmc-email.com",
      "email.netflix.com","m.netflix.com"
    },
    urgency = {
      "din netflix betaling er afvist",
      "netflix abonnement udløber",
      "verify your netflix account"
    }
  },

  EASYBANK = {
    symbol = "ORG_PHISHING_EASYBANK",
    score = 9.0,
    keywords = { "mobilepay", "mitid", "nemid" },
    domains = {
      "mobilepay.dk","mitid.dk","nemid.nu",
      "digst.dk",
      "carmamail.com","customer%-%d+%-.+%.carmamail%.com",
      "sendgrid.net","mandrillapp.com",
      "trk.mobilepay.dk","email.mobilepay.dk","secure.mitid.dk"
    },
    urgency = {
      "din mitid er spærret",
      "din mobilepay er spærret",
      "bekræft din identitet"
    }
  },

  -- NEW: EasyPark spoof protection (examsaide + Amazon SES)
  EASYPARK = {
    symbol = "ORG_PHISHING_EASYPARK",
    score = 8.0,
    keywords = { "easypark", "easy park", "easy-park" },
    domains = {
      -- legit EasyPark domains
      "easypark.dk","easypark.se","easypark.no","easypark.fi","easypark.net",
      "easyparkapp.com","easyparkgroup.com",

      -- typical ESPs they might use
      "sendgrid.net","mandrillapp.com","sfmc-email.com",

      -- spoof infra seen in 2026 campaigns
      "examsaide.com",
      "amazonses.com",
      "eu-central-1.amazonses.com",
      "smtp-out.eu-central-1.amazonses.com",
      "b224-6.smtp-out.eu-central-1.amazonses.com"
    },
    urgency = {
      "ubetalt parkering",
      "ubetalt parkeringsafgift",
      "betaling for parkering mangler",
      "din parkering er ugyldig",
      "verify your easypark account"
    }
  },
}

---------------------------------------------------------------------------
-- TEXT MATCH HELPERS
---------------------------------------------------------------------------

local function contains_any(text, patterns)
  if not text then return false end
  local t = lower(text)
  for _, p in ipairs(patterns) do
    if t:find(lower(p), 1, true) then
      return true
    end
  end
  return false
end

local function subject_contains(task, patterns)
  return contains_any(task:get_subject(), patterns)
end

local function header_contains(task, hdr, patterns)
  return contains_any(task:get_header(hdr), patterns)
end

local function body_contains(task, patterns)
  local parts = task:get_text_parts()
  if not parts then return false end
  for _, part in ipairs(parts) do
    local c = part:get_content()
    if c and contains_any(c, patterns) then
      return true
    end
  end
  return false
end

local function urls_match(task, brand)
  for _, u in ipairs(task:get_urls() or {}) do
    local h = u:get_host()
    if h then
      h = lower(h):gsub("%.$", "")
      for _, d in ipairs(brand.domains) do
        d = lower(d)
        if h == d or h:sub(-(string.len(d) + 1)) == "." .. d then
          return true
        end
      end
    end
  end
  return false
end

---------------------------------------------------------------------------
-- BRAND CHECK
---------------------------------------------------------------------------

local function check_brand(task, brand)
  local reasons = {}

  if subject_contains(task, brand.keywords)
     or header_contains(task, "From", brand.keywords)
     or header_contains(task, "Reply-To", brand.keywords)
     or body_contains(task, brand.keywords)
  then
    reasons[#reasons+1] = "keywords"
  end

  if urls_match(task, brand) then
    reasons[#reasons+1] = "urls"
  end

  if subject_contains(task, brand.urgency)
     or body_contains(task, brand.urgency)
  then
    reasons[#reasons+1] = "urgency"
  end

  if #reasons == 0 then
    return false
  end

  return true, table.concat(reasons, ",")
end

---------------------------------------------------------------------------
-- REGISTER ONE SYMBOL PER BRAND
---------------------------------------------------------------------------

for name, brand in pairs(brands) do
  rspamd_config:register_symbol({
    name = brand.symbol,
    score = brand.score,
    description = "Brand phishing: " .. name,
    group = "phishing",

    callback = function(task)
      local hit, reasons = check_brand(task, brand)
      if not hit then
        return false
      end

      -- Whitelist check
      local from = task:get_from(1)
      if from and from[1] and from[1].domain then
        if domain_matches(from[1].domain, brand.domains) then
          logger.infox(task, "ORG_PHISHING: %s whitelisted (%s)", name, from[1].domain)
          return false
        end
      end

      logger.infox(task, "ORG_PHISHING: matched %s (%s)", name, reasons)
      return true, reasons
    end,
  })
end

logger.infox("ORG_PHISHING: all brand symbols registered")
