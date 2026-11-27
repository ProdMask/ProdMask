package sqldump

// ValueKind says what a literal in a row was.
type ValueKind uint8

const (
	// ValNull is NULL.
	ValNull ValueKind = iota
	// ValString is text, decoded as UTF-8.
	ValString
	// ValBinary is raw bytes: a string under the binary character set, or
	// after _binary.
	ValBinary
	// ValHex is the bytes of 0x41 or X'41'. The column decides whether they
	// are text.
	ValHex
	// ValNumber is a number, kept as its text. TRUE and FALSE are 1 and 0.
	ValNumber
	// ValBit is the digits of b'0101' or 0b0101.
	ValBit
	// ValDefault is DEFAULT, for the column's default to fill.
	ValDefault
)

// Value is one literal of a row. Bytes is valid until the next value is read.
type Value struct {
	Kind  ValueKind
	Bytes []byte
	// Cut is set when the value was longer than the cap and the rest was
	// skipped.
	Cut bool

	// src is the character set a string literal was decoded under.
	src csKind
}

var (
	numOne  = []byte("1")
	numZero = []byte("0")
)

// readValue reads one literal of a row, and checks that it stands alone: the
// next token must be a comma or a closing parenthesis. It returns the reason
// when the value, and so the rest of the statement, can't be read.
func (st *stmt) readValue() (Value, Reason) {
	v, why := st.value()
	st.lx.override = csNone
	if why != "" {
		return Value{}, why
	}
	if p := st.peek(); !p.isSym(',') && !p.isSym(')') {
		return Value{}, ReasonExpression
	}
	return v, ""
}

func (st *stmt) value() (Value, Reason) {
	t := st.next()
	switch t.kind {
	case tokString, tokHex, tokBit:
		return st.literal(t)
	case tokNum:
		return st.number(nil, t), ""
	case tokSym:
		if t.sym == '-' || t.sym == '+' {
			sign := []byte(nil)
			if t.sym == '-' {
				sign = []byte{'-'}
			}
			if n := st.next(); n.kind == tokNum {
				return st.number(sign, n), ""
			}
		}
	case tokWord:
		switch {
		case t.is("null"):
			return Value{Kind: ValNull}, ""
		case t.is("true"):
			return Value{Kind: ValNumber, Bytes: numOne}, ""
		case t.is("false"):
			return Value{Kind: ValNumber, Bytes: numZero}, ""
		case t.is("default"):
			return Value{Kind: ValDefault}, ""
		case len(t.text) > 1 && t.text[0] == '_':
			return st.introduced(t)
		}
	}
	return Value{}, ReasonExpression
}

// number keeps a number's text, signed or not, in a buffer the next token
// can't overwrite.
func (st *stmt) number(sign []byte, t token) Value {
	r := st.r
	r.num = append(append(r.num[:0], sign...), t.text...)
	return Value{Kind: ValNumber, Bytes: r.num}
}

// introduced reads _binary '...', _utf8mb4 X'...' and the like: the literal
// that follows is decoded in the named character set.
func (st *stmt) introduced(intro token) (Value, Reason) {
	info, _, ok := lookupCharset(string(intro.text[1:]))
	if !ok {
		return Value{}, ReasonExpression
	}
	if !info.decoded {
		return Value{}, ReasonCharset
	}
	st.lx.override = info.kind
	t := st.next()
	switch t.kind {
	case tokString, tokHex, tokBit:
		return st.literal(t)
	}
	return Value{}, ReasonExpression
}

// literal reads a string, hex or bit literal that began with the token t, with
// the strings that follow it and the COLLATE after it.
func (st *stmt) literal(t token) (Value, Reason) {
	lx := st.lx
	var v Value
	switch t.kind {
	case tokString:
		b, cut := st.joinStrings()
		v = Value{Kind: ValString, Bytes: b, Cut: cut, src: lx.effectiveCS()}
		if lx.effectiveCS() == csBinary {
			v.Kind = ValBinary
		}
	case tokHex:
		if t.bad {
			return Value{}, ReasonExpression
		}
		v = Value{Kind: ValHex, Bytes: t.text, Cut: t.cut}
		switch lx.override {
		case csBinary:
			v.Kind = ValBinary
		case csKeep:
			v.Kind = ValString
		case csLatin1:
			v.Kind = ValString
			v.Bytes = st.r.latin1(t.text)
		}
	case tokBit:
		if t.bad {
			return Value{}, ReasonExpression
		}
		v = Value{Kind: ValBit, Bytes: t.text, Cut: t.cut}
	}
	if st.peek().is("collate") {
		st.next()
		st.next()
	}
	return v, ""
}

// latin1 converts bytes from latin1 to UTF-8, into a buffer of the reader's.
func (r *reader) latin1(b []byte) []byte {
	r.conv = appendLatin1(r.conv[:0], b)
	return r.conv
}
