'use strict';

var cheerio = require('cheerio');
var { JSDOM } = require('jsdom');
var createDOMPurify = require('dompurify');

// Create DOMPurify instance for secure sanitization
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);


var shorthandProperties = {
	"image": "image:url",
	"video": "video:url",
	"audio": "audio:url"
}

var keyBlacklist = [
	'__proto__',
	'constructor',
	'prototype'
]

// Sanitize content using DOMPurify + additional safety checks
function sanitizeContent(content, options) {
	if (!content || typeof content !== 'string') {
		return '';
	}
	
	// DOMPurify configuration for OpenGraph content (strip all HTML, keep text)
	var purifyConfig = {
		ALLOWED_TAGS: [], // Remove all HTML tags
		ALLOWED_ATTR: [], // Remove all attributes  
		KEEP_CONTENT: true, // Keep text content
		ALLOW_DATA_ATTR: false,
		ALLOW_UNKNOWN_PROTOCOLS: false,
		SANITIZE_DOM: true
	};
	
	// Allow custom DOMPurify config from options
	if (options && options.sanitization) {
		purifyConfig = Object.assign(purifyConfig, options.sanitization);
	}
	
	// First pass: DOMPurify for HTML sanitization
	var sanitized = DOMPurify.sanitize(content, purifyConfig);
	
	if (typeof sanitized !== 'string') {
		return '';
	}
	
	// Second pass: Additional filtering for non-HTML dangerous patterns
	// Critical for Electron apps without contextIsolation
	var dangerousPatterns = [
		/javascript:/gi,
		/vbscript:/gi, 
		/livescript:/gi,
		/file:/gi,
		/data:/gi,
		/\brequire\s*\(/gi,
		/\bprocess\./gi,
		/\bglobal\./gi,
		/\bmodule\./gi,
		/\bexports\./gi,
		/\bchild_process\b/gi,
		/\beval\s*\(/gi,
		/\bFunction\s*\(/gi,
		/\bsetTimeout\s*\(/gi,
		/\bsetInterval\s*\(/gi
	];
	
	// Remove dangerous patterns
	dangerousPatterns.forEach(function(pattern) {
		sanitized = sanitized.replace(pattern, '');
	});
	
	// Limit content length
	var maxLength = (options && options.maxContentLength) || 10000;
	if (sanitized.length > maxLength) {
		sanitized = sanitized.substring(0, maxLength);
	}
	
	return sanitized.trim();
}

// Simple property key sanitization (keep existing secure logic)
function sanitizePropertyKey(key, options) {
	if (!key || typeof key !== 'string') {
		return '';
	}
	
	// Limit key length
	var maxLength = (options && options.maxPropertyLength) || 200;
	if (key.length > maxLength) {
		return '';
	}
	
	// Convert to lowercase for consistency
	key = key.toLowerCase().trim();
	
	// Allow only safe characters for OpenGraph properties
	var allowedChars = /^[a-zA-Z0-9_\-:.]+$/;
	if (!allowedChars.test(key)) {
		// Clean up the key
		key = key.replace(/[^a-zA-Z0-9_\-:.]/g, '');
	}
	
	return key;
}

exports = module.exports = function(url, cb, options){
  var userAgent = (options || {}).userAgent || 'NodeOpenGraphCrawler (https://github.com/samholmes/node-open-graph)'
	exports.getHTML(url, userAgent, options, function(err, html){
		if (err) return cb(err);

		try {
			var parsedMeta = exports.parse(html, options);
		}
		catch (parseErr) {
			cb(parseErr);
		}

		cb(null, parsedMeta);
	})
}


exports.getHTML = function(url, userAgent, options, cb){
	// Handle different argument patterns for backward compatibility
	if (typeof options === 'function') {
		cb = options;
		options = {};
	}
	
	// Handle protocol-less URLs (maintain existing behavior)
	var purl = require('url').parse(url);
	if (!purl.protocol)
		purl = require('url').parse("https://"+url);
	url = require('url').format(purl);

	fetch(url, {
		headers: { 
			'User-Agent': userAgent 
		}
	})
	.then(function(response) {
		if (!response.ok) {
			throw new Error("Request failed with HTTP status code: " + response.status);
		}
		return response.text();
	})
	.then(function(body) {
		cb(null, body);
	})
	.catch(function(err) {
		cb(err);
	});
}


exports.parse = function($, options){
	options = options || {};

	if (typeof $ === 'string')
		$ = cheerio.load($);

	// Check for xml namespace
	var namespace,
		$html = $('html');

	if ($html.length)
	{
		var attribKeys = Object.keys($html[0].attribs);

		attribKeys.some(function(attrName){
			var attrValue = $html.attr(attrName);

			if (attrValue.toLowerCase() === 'http://opengraphprotocol.org/schema/'
				&& attrName.substring(0, 6) == 'xmlns:')
			{
				namespace = attrName.substring(6);
				return false;
			}
		})
	}
	else if (options.strict)
		return null;

	if (!namespace)
		// If no namespace is explicitly set..
		if (options.strict)
			// and strict mode is specified, abort parse.
			return null;
		else
			// and strict mode is not specific, then default to "og"
			namespace = "og";

	var meta = Object.create(null),
		metaTags = $('meta');

	metaTags.each(function() {
		var element = $(this),
			propertyAttr = element.attr('property');

		// If meta element isn't an "og:" property, skip it
		if (!propertyAttr || propertyAttr.substring(0, namespace.length) !== namespace)
			return;

		var property = propertyAttr.substring(namespace.length+1),
			content = element.attr('content');

		// Sanitize content for security
		content = sanitizeContent(content, options);
		if (!content) return; // Skip empty content after sanitization

		// Sanitize the property name first
		property = sanitizePropertyKey(property, options);
		if (!property) return; // Skip if property becomes invalid after sanitization

		// If property is a shorthand for a longer property,
		// Use the full property
		property = shorthandProperties[property] || property;
		
		// Ensure property is still a valid string after shorthand lookup
		if (!property || typeof property !== 'string') return;

		var key, tmp,
			ptr = meta,
			keys = property.split(':', 4);

		// Sanitize each key component for security
		for (var i = 0; i < keys.length; i++) {
			keys[i] = sanitizePropertyKey(keys[i], options);
			if (!keys[i] && i < keys.length - 1) return; // Skip if intermediate key becomes invalid
		}

		// we want to leave one key to assign to so we always use references
		// as long as there's one key left, we're dealing with a sub-node and not a value

		while (keys.length > 1) {
			key = keys.shift();

			if (keyBlacklist.includes(key.toLowerCase())) return;

			if (Array.isArray(ptr[key])) {
				// the last index of ptr[key] should become
				// the object we are examining.
				tmp = ptr[key].length-1;
				ptr = ptr[key];
				key = tmp;
			}

			if (typeof ptr[key] === 'string') {
				// if it's a string, convert it
				ptr[key] = { '': ptr[key] };
			} else if (ptr[key] === undefined) {
				// create a new key
				ptr[key] = Object.create(null);
			}

			// move our pointer to the next subnode
			ptr = ptr[key];
		}

		// deal with the last key
		key = keys.shift();
		if (keyBlacklist.includes(key.toLowerCase())) return;

		if (ptr[key] === undefined) {
			ptr[key] = content;
		} else if (Array.isArray(ptr[key])) {
			ptr[key].push(content);
		} else {
			ptr[key] = [ ptr[key], content ];
		}
	});


	// If no 'og:title', use title tag
    if (!('title' in meta)) {
    	var titleText = $('title').text();
    	meta.title = sanitizeContent(titleText, options);
    }


	// Temporary fallback for image meta.
	// Fallback to the first image on the page.
	// In the future, the image property could be populated
	// with an array of images, maybe.
  	if (!('image' in meta)) {
		const img = $('img');

		// If there are image elements in the page
		if(img.length){
			var imgObj = {};
			var imgSrc = $('img').attr('src');
			imgObj.url = sanitizeContent(imgSrc, options);
			
			// Only include image if URL is valid after sanitization
			if (imgObj.url) {
				// Set image width and height properties if respective attributes exist
				var imgWidth = $('img').attr('width');
				var imgHeight = $('img').attr('height');
				
				if(imgWidth) {
					imgWidth = sanitizeContent(imgWidth, options);
					if (imgWidth && /^\d+$/.test(imgWidth)) {
						imgObj.width = imgWidth;
					}
				}
				if(imgHeight) {
					imgHeight = sanitizeContent(imgHeight, options);
					if (imgHeight && /^\d+$/.test(imgHeight)) {
						imgObj.height = imgHeight;
					}
				}

				meta['image'] = imgObj;
			}
		}

	}

	return meta;
}
