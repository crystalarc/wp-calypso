/** @format */

/**
 * External dependencies
 */
import cookie from 'cookie';
import debugFactory from 'debug';
import url from 'url';
import { assign } from 'lodash';
import request from 'superagent';

const debug = debugFactory( 'calypso:analytics:sem' );

/**
 * Const variables.
 */
const UTM_COOKIE_MAX_AGE = 60 * 60 * 24 * 365;
const MAX_UTM_LENGTH = 128;
const MAX_URL_PARAM_VALUE_LENGTH = 50;
const MAX_KEYWORD_PARAM_VALUE_LENGTH = 80;
const MAX_GCLID_PARAM_VALUE_LENGTH = 100;
// These are the URL params that end up in the `ad_details` cookie
const URL_PARAM_WHITELIST = [
	'adgroupid',
	'campaignid',
	'device',
	'gclid',
	'gclsrc',
	'fbclid',
	'keyword',
	'matchtype',
	'network',
	'type',
	'term',
	'utm_campaign',
	'utm_content',
	'utm_medium',
	'utm_source',
	'utm_term',
	'targetid', // QuanticMind
	'locationid', // QuanticMind
	'ref',
	'format', // amp/non-amp
];

function isValidUtmSurceOrCampaign( value ) {
	return null !== value.match( new RegExp( '^[a-zA-Z\\d_\\-]{1,' + MAX_UTM_LENGTH + '}$' ) );
}

function isValidOtherUrlParamValue( key, value ) {
	if ( 'gclid' === key ) {
		return value.length <= MAX_GCLID_PARAM_VALUE_LENGTH;
	} else if ( 'keyword' === key ) {
		return value.length <= MAX_KEYWORD_PARAM_VALUE_LENGTH;
	}

	return value.length <= MAX_URL_PARAM_VALUE_LENGTH;
}

function isValidWhitelistedUrlParamValue( key, value ) {
	if ( -1 === URL_PARAM_WHITELIST.indexOf( key ) ) {
		return false;
	} else if ( 'utm_source' === key || 'utm_campaign' === value ) {
		return isValidUtmSurceOrCampaign( value );
	}

	return isValidOtherUrlParamValue( key, value );
}

function setUtmCookie( name, value ) {
	document.cookie = cookie.serialize( name, value, {
		path: '/',
		maxAge: UTM_COOKIE_MAX_AGE,
		// domain: '.wordpress.com',
	} );
}

/**
 * Decodes a base64 encoded string
 *
 * @param {String} str The url-safe base64 encoded string
 * @return {String} The decoded string
 */
function urlSafeBase64DecodeString( str ) {
	const decodeMap = {
		'-': '+',
		_: '/',
		'.': '=',
	};

	return atob( str.replace( /[-_.]/g, ch => decodeMap[ ch ] ) );
}

/**
 * Decodes a URL param encoded by AMP's linker.js
 * See also https://github.com/ampproject/amphtml/blob/master/extensions/amp-analytics/linker-id-receiving.md
 *
 * @param {String} value Value to be decoded
 * @return {null|Object} null or and object containing key/value pairs
 */
function parseAmpEncodedParams( value ) {
	value = value
		.split( '*' )
		.filter( val => val.length )
		.slice( 2 );
	// return null if empty or we have an odd number of elements
	if ( 0 === value.length || 0 !== value.length % 2 ) {
		return null;
	}
	const keyValMap = {};
	for ( let i = 0; i < value.length; i += 2 ) {
		keyValMap[ value[ i ] ] = urlSafeBase64DecodeString( value[ i + 1 ] );
	}

	return keyValMap;
}

/**
 * Initializes the cookies for SEM attribution `ad_details` and `ad_timestamp`.
 */
export function updateSEM() {
	const parsedUrl = url.parse( document.location.href, true );
	let query = parsedUrl.query;

	debug( 'Original query:', query );

	// If `tk_amp` is present extract its values but prioritize the ones explicitly present in original URL query.
	// May contain:
	// - whitelisted sem url params as in URL_PARAM_WHITELIST
	// - client_id
	// - affiliate
	// - aff
	if ( 'tk_amp' in query ) {
		const tk_amp = parseAmpEncodedParams( query.tk_amp );
		debug( 'tk_amp:', tk_amp );
		query = assign( {}, tk_amp, query );
	}

	debug( 'Merged query:', query );

	// Sanitize query params
	const sanitized_query = {};
	Object.keys( query ).forEach( key => {
		const value = query[ key ];
		if ( isValidWhitelistedUrlParamValue( key, value ) ) {
			sanitized_query[ key ] = value;
		}
	} );

	// Cross domain tracking for Tracks
	if ( query.client_id ) {
		window._tkq.push( [ 'identifyAnonUser', query.client_id ] );
	}

	// Affiliate tracking
	// TODO: if this works remove the rest of the the affiliate trcking logic firing from /start/about/
	if ( query.aff && ! isNaN( query.aff ) ) {
		window._tkq.push( [
			'recordEvent',
			'calypso_refer_visit',
			{
				flow: '',
				// The current page without any query params
				page: `${ parsedUrl.host }${ parsedUrl.pathname }`,
			},
		] );

		request
			.post( 'https://refer.wordpress.com/clicks/67402' )
			.set( 'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8' )
			.send( {
				affiliate_id: query.aff,
				campaign_id: query.cid || '',
				sub_id: query.sid || '',
				referrer: document.location.href,
			} )
			.withCredentials()
			.then( res => {
				debug( 'Affiliate tracking: ', res );
			} );
	}

	// Drop SEM cookie update if either of these is missing
	if ( ! sanitized_query.utm_source || ! sanitized_query.utm_campaign ) {
		debug( 'Missing utm_source or utm_campaign.' );
		return;
	}

	// Regenerate sanitized query string
	let sanitized_query_string = [];
	Object.keys( sanitized_query ).forEach( key => {
		sanitized_query_string.push(
			encodeURIComponent( key ) + '=' + encodeURIComponent( sanitized_query[ key ] )
		);
	} );

	sanitized_query_string = sanitized_query_string.join( '&' );

	if ( sanitized_query_string ) {
		debug( 'ad_details: ' + sanitized_query_string );
		setUtmCookie( 'ad_details', sanitized_query_string );
		setUtmCookie( 'ad_timestamp', Math.floor( new Date().getTime() / 1000 ) );
	}
}
