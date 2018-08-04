/** ----------------------------------------------------------------------
 * Copyright (c) 2012 Yves-Marie K. Rinquin
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ----------------------------------------------------------------------
 *
 * ISAAC is a cryptographically secure pseudo-random number generator
 * (or CSPRNG for short) designed by Robert J. Jenkins Jr. in 1996 and
 * based on RC4. It is designed for speed and security.
 *
 * ISAAC's informations & analysis:
 *   http://burtleburtle.net/bob/rand/isaac.html
 * ISAAC's implementation details:
 *   http://burtleburtle.net/bob/rand/isaacafa.html
 *
 * ISAAC succesfully passed TestU01
 *
 * ----------------------------------------------------------------------
 * Output: 			[ 0x00000000; 0xffffffff]
 * Numbers range:  	[-2147483648; 2147483647]
 * ----------------------------------------------------------------------
  Usage. Simple including:
  
    <script src="isaac.js">//include ISAAC CSPRNG</script>
    <script>
 		isaac.seed(Math.random() * 0xffffffff); 	//dynamic initial seed from 0 to 0xffffffff = 4294967295 = 2^32,
 													//This means one integer [-2^31;(+2^31-1)] in range [-2147483648; 2147483647],
 													//if first bit reserved for negative numbers.
 
 		//isaac.seed('static_string_seed'); 		//or this seed, can be a string.
 		
 		var random_number = isaac.random(); 		//number, like return console.log(Math.random());
 		var rand_number = isaac.rand();				//whole integer in range [-2147483648; 2147483647], like return
													//console.log(	crypto.getRandomValues( new Uint32Array(100) )	);
 
 		document.write(								//output.
 				' isaac.random(): ', random_number	//isaac.random(): 0.3813510288018733
 			+	'<br> isaac.rand(): ', rand_number	//isaac.rand(): -1978938723
 		);
 	 </script>
 */


/* js string (ucs-2/utf16) to a 32-bit integer (utf-8 chars, little-endian) array */
String.prototype.toIntArray = function() {
  var w1, w2, u, r4 = [], r = [], i = 0;
  var s = this + '\0\0\0'; // pad string to avoid discarding last chars
  var l = s.length - 1;

  while(i <= l) {
    w1 = s.charCodeAt(i++);
    w2 = s.charCodeAt(i+1);
    if       (w1 < 0x0080) {
      // 0x0000 - 0x007f code point: basic ascii
      r4.push(w1);
    } else if(w1 < 0x0800) {
      // 0x0080 - 0x07ff code point
      r4.push(((w1 >>>  6) & 0x1f) | 0xc0);
      r4.push(((w1 >>>  0) & 0x3f) | 0x80);
    } else if((w1 & 0xf800) != 0xd800) {
      // 0x0800 - 0xd7ff / 0xe000 - 0xffff code point
      r4.push(((w1 >>> 12) & 0x0f) | 0xe0);
      r4.push(((w1 >>>  6) & 0x3f) | 0x80);
      r4.push(((w1 >>>  0) & 0x3f) | 0x80);
    } else if(((w1 & 0xfc00) == 0xd800)
           && ((w2 & 0xfc00) == 0xdc00)) {
      // 0xd800 - 0xdfff surrogate / 0x10ffff - 0x10000 code point
      u = ((w2 & 0x3f) | ((w1 & 0x3f) << 10)) + 0x10000;
      r4.push(((u >>> 18) & 0x07) | 0xf0);
      r4.push(((u >>> 12) & 0x3f) | 0x80);
      r4.push(((u >>>  6) & 0x3f) | 0x80);
      r4.push(((u >>>  0) & 0x3f) | 0x80);
      i++;
    } else {
      // invalid char
    }
    /* add integer (four utf-8 value) to array */
    if(r4.length > 3) {
      // little endian
      r.push((r4.shift() <<  0) | (r4.shift() <<  8) |
             (r4.shift() << 16) | (r4.shift() << 24));
    }
  }

  return r;
}

/* isaac module pattern */
var isaac = (function(){

  /* private: internal states */
  var m = Array(256), // internal memory
      acc = 0,        // accumulator
      brs = 0,        // last result
      cnt = 0,        // counter
      r = Array(256), // result array
      gnt = 0;        // generation counter

	seed(Math.random() * 0xffffffff);								//random seed, using default Math.random(), if this was been not redefined.
	//if this string will be commented, start image in canvas on load the page, without moving cursor - will be static,
	//and then this changed after short timeout... You cann't save correct seed of this page in this case.
	
//	seed('test length');											//initial seed. This can be a string hash or string like this
//	seed(Math.random().toString(36).replace('.', ''));				//or, like this.

//	reseed after including (see isaac-test.htm source code):
//		1.	isaac.reset();
//		2.	isaac.seed();
//			if seed is a string isaac.seed('string'), no need to do isaac.reset()
//			In this case, string go to array, and after check this, reset will be doing automatically.


  /* private: 32-bit integer safe adder */
  function add(x, y) {
    var lsb = (x & 0xffff) + (y & 0xffff);
    var msb = (x >>>   16) + (y >>>   16) + (lsb >>> 16);
    return (msb << 16) | (lsb & 0xffff);
  }

  /* public: initialisation */
  function reset() {
    acc = brs = cnt = 0;
    for(var i = 0; i < 256; ++i)
      //console.log('m[i]', m[i], 'r[i]', r[i]);	//in first start - this undefined both
	  m[i] = r[i] = 0;
    gnt = 0;
  }

  /* public: seeding function */
  function seed(s) {
    var a, b, c, d, e, f, g, h, i;

    /* seeding the seeds of love */
    a = b = c = d =
    e = f = g = h = 0x9e3779b9; /* the golden ratio */

    if(s && typeof(s) === 'string')
      s = s.toIntArray();

    if(s && typeof(s) === 'number') {
      s = [s];
    }

	//console.log(s);
    if(s instanceof Array) {
      //console.log('\n\n\n acc', acc, 'brs', brs, 'cnt', cnt, 'm', m, 'r', r, 'gnt', gnt);
      reset();
      for(i = 0; i < s.length; i++)
        r[i & 0xff] += (typeof(s[i]) === 'number') ? s[i] : 0;
    }

    /* private: seed mixer */
    function seed_mix() {
      a ^= b <<  11; d = add(d, a); b = add(b, c);
      b ^= c >>>  2; e = add(e, b); c = add(c, d);
      c ^= d <<   8; f = add(f, c); d = add(d, e);
      d ^= e >>> 16; g = add(g, d); e = add(e, f);
      e ^= f <<  10; h = add(h, e); f = add(f, g);
      f ^= g >>>  4; a = add(a, f); g = add(g, h);
      g ^= h <<   8; b = add(b, g); h = add(h, a);
      h ^= a >>>  9; c = add(c, h); a = add(a, b);
    }

    for(i = 0; i < 4; i++) /* scramble it */
      seed_mix();

    for(i = 0; i < 256; i += 8) {
      if(s) { /* use all the information in the seed */
        a = add(a, r[i + 0]); b = add(b, r[i + 1]);
        c = add(c, r[i + 2]); d = add(d, r[i + 3]);
        e = add(e, r[i + 4]); f = add(f, r[i + 5]);
        g = add(g, r[i + 6]); h = add(h, r[i + 7]);
      }
      seed_mix();
      /* fill in m[] with messy stuff */
      m[i + 0] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d;
      m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
    }
    if(s) {
      /* do a second pass to make all of the seed affect all of m[] */
      for(i = 0; i < 256; i += 8) {
        a = add(a, m[i + 0]); b = add(b, m[i + 1]);
        c = add(c, m[i + 2]); d = add(d, m[i + 3]);
        e = add(e, m[i + 4]); f = add(f, m[i + 5]);
        g = add(g, m[i + 6]); h = add(h, m[i + 7]);
        seed_mix();
        /* fill in m[] with messy stuff (again) */
        m[i + 0] = a; m[i + 1] = b; m[i + 2] = c; m[i + 3] = d;
        m[i + 4] = e; m[i + 5] = f; m[i + 6] = g; m[i + 7] = h;
      }
    }

    prng(); /* fill in the first set of results */
    gnt = 256;  /* prepare to use the first set of results */;
  }

  /* public: isaac generator, n = number of run */
  function prng(n){
    var i, x, y;

    n = (n && typeof(n) === 'number')
      ? Math.abs(Math.floor(n)) : 1;

    while(n--) {
      cnt = add(cnt,   1);
      brs = add(brs, cnt);

      for(i = 0; i < 256; i++) {
        switch(i & 3) {
          case 0: acc ^= acc <<  13; break;
          case 1: acc ^= acc >>>  6; break;
          case 2: acc ^= acc <<   2; break;
          case 3: acc ^= acc >>> 16; break;
        }
        acc        = add(m[(i +  128) & 0xff], acc); x = m[i];
        m[i] =   y = add(m[(x >>>  2) & 0xff], add(acc, brs));
        r[i] = brs = add(m[(y >>> 10) & 0xff], x);
      }
    }
  }

  /* public: return a random number between */
  function rand() {
    if(!gnt--) {
      prng(); gnt = 255;
    }
    return r[gnt];
  }

  /* public: return internals in an object*/
  function internals(){
    return {a: acc, b: brs, c: cnt, m: m, r: r};
  }

  /* public: output*/
  function random(){//output, like return default Math.random() function.
    return 0.5 + this.rand() * 2.3283064365386963e-10; // 2^-32
	//Warning!
	//2^32 = 2.32830643653869628906e-10 (!== and ≈) 2.3283064365386963e-10
	//so can be small and rare artifacts or strips in canvas.
	//recommend to using isaac.rand() to get CSPRNG values.
	//This return values, like console.log(	crypto.getRandomValues( new Uint32Array(100) )	);
  }	
  
  /* return class object */
  return {
    'reset': reset,
    'seed':  seed,
    'prng':  prng,
    'rand':  rand,
    'random': random,
    'internals': internals
  };
})(); /* declare and execute */

( "undefined" !== ( typeof( module ) ) ) && module.exports && ( module.exports = isaac );

/* public: output*/ //old code
//isaac.random = function() {//output, like return default Math.random() function.
//  return 0.5 + this.rand() * 2.3283064365386963e-10; // 2^-32
	//Warning!
	//2^32 = 2.32830643653869628906e-10 (!== and ≈) 2.3283064365386963e-10
	//so can be small and rare artifacts or strips in canvas.
	//recommend to using isaac.rand() to get CSPRNG values.
	//This return values, like console.log(	crypto.getRandomValues( new Uint32Array(100) )	);
//}
