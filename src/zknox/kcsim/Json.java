package zknox.kcsim;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON reader (objects, arrays, strings, numbers, booleans, null) for the reference vectors. */
final class Json {
  private final String s;
  private int i;

  private Json(String s) {
    this.s = s;
  }

  static Object parse(String text) {
    Json j = new Json(text);
    Object v = j.value();
    j.ws();
    if (j.i != j.s.length()) {
      throw new IllegalArgumentException("JSON : contenu après la valeur");
    }
    return v;
  }

  @SuppressWarnings("unchecked")
  static Object path(Object root, String... keys) {
    Object cur = root;
    for (String k : keys) {
      if (cur instanceof Map) {
        cur = ((Map<String, Object>) cur).get(k);
      } else if (cur instanceof List) {
        cur = ((List<Object>) cur).get(Integer.parseInt(k));
      } else {
        throw new IllegalArgumentException("JSON : chemin invalide " + k);
      }
      if (cur == null) {
        throw new IllegalArgumentException("JSON : clé absente " + k);
      }
    }
    return cur;
  }

  private void ws() {
    while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
      i++;
    }
  }

  private Object value() {
    ws();
    char c = s.charAt(i);
    if (c == '{') {
      Map<String, Object> m = new LinkedHashMap<>();
      i++;
      ws();
      if (s.charAt(i) == '}') {
        i++;
        return m;
      }
      while (true) {
        ws();
        String k = string();
        ws();
        expect(':');
        m.put(k, value());
        ws();
        if (s.charAt(i) == ',') {
          i++;
        } else {
          expect('}');
          return m;
        }
      }
    }
    if (c == '[') {
      List<Object> l = new ArrayList<>();
      i++;
      ws();
      if (s.charAt(i) == ']') {
        i++;
        return l;
      }
      while (true) {
        l.add(value());
        ws();
        if (s.charAt(i) == ',') {
          i++;
        } else {
          expect(']');
          return l;
        }
      }
    }
    if (c == '"') {
      return string();
    }
    if (s.startsWith("true", i)) {
      i += 4;
      return Boolean.TRUE;
    }
    if (s.startsWith("false", i)) {
      i += 5;
      return Boolean.FALSE;
    }
    if (s.startsWith("null", i)) {
      i += 4;
      return null;
    }
    int start = i;
    while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
      i++;
    }
    return s.substring(start, i);
  }

  private String string() {
    expect('"');
    StringBuilder b = new StringBuilder();
    while (s.charAt(i) != '"') {
      char c = s.charAt(i++);
      if (c == '\\') {
        char e = s.charAt(i++);
        switch (e) {
          case 'n': b.append('\n'); break;
          case 't': b.append('\t'); break;
          case 'u': b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; break;
          default: b.append(e);
        }
      } else {
        b.append(c);
      }
    }
    i++;
    return b.toString();
  }

  private void expect(char c) {
    if (s.charAt(i) != c) {
      throw new IllegalArgumentException("JSON : '" + c + "' attendu en position " + i);
    }
    i++;
  }
}
