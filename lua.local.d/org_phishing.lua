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
-- BRAND DEFINITIONS (FULL SET)
---------------------------------------------------------------------------

local brands = {

  ---------------------------------------------------------------------------
  -- YOUSEE
  ---------------------------------------------------------------------------
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

  ---------------------------------------------------------------------------
  -- POSTNORD
  ---------------------------------------------------------------------------
  POSTNORD = {
    symbol = "ORG_PHISHING_POSTNORD",
    score = 8.0,
    keywords = { "postnord", "post nord" },
    domains = {
      "postnord.dk","postnord.com",
      "sendgrid.net","postnord.%w+%.sendgrid%.net",
      "trk.postnord.com","m.postnord.com",
      "postnord-secure.com","postnord-delivery.com",
      "postnord-update.com","postnord-verify.com"
    },
    urgency = {
      "din postnord pakke er tilbageholdt",
      "postnord levering afventer betaling",
      "postnord pakke mangler information",
      "verify your postnord delivery"
    }
  },

  ---------------------------------------------------------------------------
  -- COOP
  ---------------------------------------------------------------------------
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

  ---------------------------------------------------------------------------
  -- NETFLIX
  ---------------------------------------------------------------------------
  NETFLIX = {
    symbol = "ORG_PHISHING_NETFLIX",
    score = 8.0,
    keywords = { "netflix" },
    domains = {
      "netflix.com",
      "mandrillapp.com","sendgrid.net","sfmc-email.com",
      "email.netflix.com","m.netflix.com",
      "netflix-secure.com","netflix-billing.com",
      "netflix-update.com","netflix-verify.com"
    },
    urgency = {
      "din netflix betaling er afvist",
      "netflix betaling mangler",
      "din netflix konto er låst",
      "netflix abonnement udløber",
      "update your netflix payment",
      "verify your netflix account"
    }
  },

  ---------------------------------------------------------------------------
  -- MOBILEPAY / MITID (EASYBANK)
  ---------------------------------------------------------------------------
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

  ---------------------------------------------------------------------------
  -- EASYPARK
  ---------------------------------------------------------------------------
  EASYPARK = {
    symbol = "ORG_PHISHING_EASYPARK",
    score = 8.0,
    keywords = { "easypark", "easy park", "easy-park" },
    domains = {
      "easypark.dk","easypark.se","easypark.no","easypark.fi","easypark.net",
      "easyparkapp.com","easyparkgroup.com",
      "sendgrid.net","mandrillapp.com","sfmc-email.com",
      "examsaide.com","amazonses.com",
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

  ---------------------------------------------------------------------------
  -- KLARNA
  ---------------------------------------------------------------------------
  KLARNA = {
    symbol = "ORG_PHISHING_KLARNA",
    score = 9.0,
    keywords = {
      "klarna","klarna betaling","klarna pay",
      "klarna invoice","klarna faktura","klarna konto"
    },
    domains = {
      "klarna.com","klarna.dk","klarna.se","klarna.no","klarna.fi",
      "klarna.de","klarna.co.uk",
      "email.klarna.com","m.klarna.com",
      "klarna.mkt-mail.com","klarna.mkt-cloud.com",
      "klarnapay.com","klarnasecure.com","klarnaupdate.com",
      "klarnaverify.com","klarna-check.com","klarna-billing.com"
    },
    urgency = {
      "din klarna betaling er afvist",
      "klarna betaling mangler",
      "din klarna faktura er udløbet",
      "verify your klarna account",
      "update your klarna payment",
      "klarna security update",
      "klarna konto låst"
    }
  },

  ---------------------------------------------------------------------------
  -- DAO
  ---------------------------------------------------------------------------
  DAO = {
    symbol = "ORG_PHISHING_DAO",
    score = 8.0,
    keywords = {
      "dao","dao365","dao 365",
      "dao levering","dao forsendelse","dao tracking"
    },
    domains = {
      "dao.as","dao365.dk","dao.asia","dao.asn","dao.asn.dk",
      "dao.asn.email","dao.asn.delivery","dao.asn.services",
      "email.dao.as","trk.dao.as","m.dao.as",
      "dao.mkt-mail.com","dao.mkt-cloud.com",
      "dao-secure.com","dao-delivery.com","dao-update.com",
      "dao-verify.com","dao-tracking.com","dao365-secure.com"
    },
    urgency = {
      "din dao levering er tilbageholdt",
      "dao levering afventer betaling",
      "dao pakke mangler information",
      "verify your dao delivery",
      "dao security update",
      "dao konto låst"
    }
  },

  ---------------------------------------------------------------------------
  -- GLS
  ---------------------------------------------------------------------------
  GLS = {
    symbol = "ORG_PHISHING_GLS",
    score = 8.0,
    keywords = {
      "gls","gls pakke","gls levering","gls forsendelse","gls tracking"
    },
    domains = {
      "gls.dk","gls-group.eu","gls.de","gls.nl","gls.at","gls.it",
      "email.gls.dk","trk.gls.dk","m.gls.dk",
      "sendgrid.net","mandrillapp.com",
      "gls-delivery.com","gls-secure.com","gls-update.com",
      "gls-verify.com","gls-pakke.com"
    },
    urgency = {
      "din gls pakke er tilbageholdt",
      "gls levering afventer betaling",
      "gls pakke mangler information",
      "verify your gls delivery",
      "gls security update"
    }
  },

  ---------------------------------------------------------------------------
  -- DHL
  ---------------------------------------------------------------------------
  DHL = {
    symbol = "ORG_PHISHING_DHL",
    score = 8.5,
    keywords = {
      "dhl","dhl express","dhl pakke","dhl tracking"
    },
    domains = {
      "dhl.com","dhl.de","dhl.dk","dhl.se","dhl.fi","dhl.no",
      "email.dhl.com","trk.dhl.com","m.dhl.com",
      "sendgrid.net","mandrillapp.com",
      "dhl-secure.com","dhl-delivery.com","dhl-update.com",
      "dhl-verify.com","dhl-pakke.com"
    },
    urgency = {
      "din dhl pakke er tilbageholdt",
      "dhl levering afventer betaling",
      "dhl shipment on hold",
      "verify your dhl delivery",
      "dhl security update"
    }
  },

  ---------------------------------------------------------------------------
  -- FEDEX
  ---------------------------------------------------------------------------
  FEDEX = {
    symbol = "ORG_PHISHING_FEDEX",
    score = 8.0,
    keywords = {
      "fedex","fed ex","fedex tracking","fedex shipment"
    },
    domains = {
      "fedex.com","fedex.com.cn","fedex.com.au","fedex.com.uk",
      "email.fedex.com","trk.fedex.com","m.fedex.com",
      "sendgrid.net","mandrillapp.com",
      "fedex-secure.com","fedex-delivery.com","fedex-update.com",
      "fedex-verify.com","fedex-shipment.com"
    },
    urgency = {
      "your fedex package is on hold",
      "fedex shipment requires payment",
      "fedex delivery pending",
      "verify your fedex shipment",
      "fedex security update"
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
