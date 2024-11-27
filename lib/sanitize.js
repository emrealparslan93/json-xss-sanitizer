'use strict';

const sanitizeHtml = require('sanitize-html');

function hasOwn(object, key) {
  const keys = Reflect.ownKeys(object).filter((item) => typeof item !== 'symbol');
  return keys.includes(key);
}

const initializeOptions = (options) => {
  const sanitizerOptions = {};
  if (hasOwn(options, 'allowedTags') && Array.isArray(options.allowedTags) && options.allowedTags.length > 0) {
    sanitizerOptions.allowedTags = options.allowedTags;
  }

  if (hasOwn(options, 'allowedAttributes') && Object.keys(options.allowedAttributes).length > 0) {
    sanitizerOptions.allowedAttributes = options.allowedAttributes;
  }

  return {
    allowedKeys: (hasOwn(options, 'allowedKeys') && Array.isArray(options.allowedKeys) && options.allowedKeys) || [],
    escapeSymbols:
      (hasOwn(options, 'escapeSymbols') && Array.isArray(options.escapeSymbols) && options.escapeSymbols) || [],
    sanitizerOptions,
  };
};

const escapeSymbol = (data, symbol) => {
  const mapping = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&apos;',
    '"': '&quot;',
  };
  if (mapping[symbol]) {
    data = data.replaceAll(mapping[symbol], symbol);
  }
  return data;
};

const escapeSymbols = (data, symbols) => {
  symbols.forEach((s) => {
    data = escapeSymbol(data, s);
  });
  return data;
};

const sanitize = (options, data) => {
  if (typeof data === 'string') {
    return sanitizeHtml(data, options.sanitizerOptions);
  }
  if (Array.isArray(data)) {
    return data.map((item) => {
      if (typeof item === 'string') {
        return sanitizeHtml(item, options.sanitizerOptions);
      }
      if (Array.isArray(item) || typeof item === 'object') {
        return sanitize(options, item);
      }
      return item;
    });
  }
  if (typeof data === 'object' && data !== null) {
    Object.keys(data).forEach((key) => {
      if (options.allowedKeys.includes(key)) {
        return;
      }
      const item = data[key];
      if (typeof item === 'string') {
        data[key] = sanitizeHtml(item, options.sanitizerOptions);
        if (options.escapeSymbols && options.escapeSymbols.length) {
          data[key] = escapeSymbols(data[key], options.escapeSymbols);
        }
      } else if (Array.isArray(item) || typeof item === 'object') {
        data[key] = sanitize(options, item);
      }
    });
  }
  return data;
};

const prepareSanitize = (data, options = {}) => {
  options = initializeOptions(options);
  return sanitize(options, data);
};

module.exports = prepareSanitize;
