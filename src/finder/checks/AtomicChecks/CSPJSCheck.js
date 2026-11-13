import { sourceTypes } from '../../../parser/types';
import { severity, confidence } from '../../attributes';

export default class CSPJSCheck {
  constructor() {
    this.id = "CSP_JS_CHECK";
    this.description = __("CSP_JS_CHECK");
    this.type = sourceTypes.JAVASCRIPT;
    this.shortenedURL = "https://git.io/JeuMe";
  }

  match(astNode, astHelper, scope){
    let location = [];
    // match e.g. details.responseHeaders["content-security-policy"] = "default-src 'self'"; Note that this does not check if the assignment is inside in the responseHeaders object because of #32
    if (astNode.type === "AssignmentExpression" && astNode.left && astNode.left.type === "MemberExpression" && astNode.left.property) {
      const headerKey = this.resolveHeaderKey(astNode.left.property, scope);
      // Only assignments with a statically resolvable key name are considered. A dynamic key could target
      // any header, so reporting it would produce noise for unrelated assignments; the original check
      // applied the same literal-only boundary.
      if (headerKey !== null && headerKey.toLowerCase() === "content-security-policy") {
        const cspValue = this.resolveCspValue(astNode.right, scope);
        location.push(this.buildLocation(astNode, cspValue));
      }
    }
    else if (astNode.type == "CallExpression") {
      if (astNode.arguments.length > 0) {
        if (astNode.arguments[0].type !== "ObjectExpression") return null;
        const found_nodes = astHelper.findNodeByType(astNode.arguments[0],
          astHelper.PropertyName,
          astHelper.PropertyDepth,
          false,
          node => (node.key.name === 'responseHeaders'));

        for (const node of found_nodes) {
          // match e.g. callback({ responseHeaders: { ...details.responseHeaders, "Content-Security-Policy": ["default-src 'none'"] }})
          if (node.value.properties) {
            for (const property of node.value.properties) {
              if (property.type === "SpreadElement" || property.type === "ExperimentalSpreadProperty") {
                // match e.g. callback({ responseHeaders: { ...details.responseHeaders, ...extraHeaders }}) where extraHeaders is a local object
                for (const finding of this.extractFromSpread(property.argument, node, scope))
                  location.push(finding);
              } else {
                const headerKey = this.resolveHeaderKey(property.key, scope);
                if (headerKey === null) {
                  location.push(this.buildLocation(node, null));
                } else if (headerKey.toLowerCase() === "content-security-policy") {
                  const cspValue = this.resolveCspValue(property.value, scope);
                  location.push(this.buildLocation(node, cspValue));
                }
              }
            }
          } // match callback({ responseHeaders: Object.assign({"Content-Security-Policy": [ "default-src 'self'" ]}, details.responseHeaders)}); as a popular stackoverflow answer suggests https://stackoverflow.com/questions/51969512/define-csp-http-header-in-electron-app
          else if (node.value.type === 'CallExpression') {
            if (node.value.arguments.length > 0) {
              for (const argument of node.value.arguments)
                if (argument.type === 'ObjectExpression')
                  for (const property of argument.properties) {
                    const headerKey = this.resolveHeaderKey(property.key, scope);
                    if (headerKey === null) {
                      location.push(this.buildLocation(node.value, null));
                    } else if (headerKey.toLowerCase() === "content-security-policy") {
                      const cspValue = this.resolveCspValue(property.value, scope);
                      location.push(this.buildLocation(node.value, cspValue));
                    }
                  }
                else if (argument.type === "Identifier") {
                  for (const finding of this.extractFromSpread(argument, node.value, scope))
                    location.push(finding);
                }
            }
          }
          // match e.g. callback({ responseHeaders }) where responseHeaders is a local object variable
          else if (node.value.type === "Identifier") {
            for (const finding of this.extractFromSpread(node.value, node, scope))
              location.push(finding);
          }
        }
      }
    }
    return location;
  }

  buildLocation(astNode, cspValue) {
    const properties = cspValue === null ? { "CSPstring": undefined, "cspUnresolved": true } : { "CSPstring": cspValue };
    return { line: astNode.loc.start.line, column: astNode.loc.start.column, id: this.id, description: this.description, shortenedURL: this.shortenedURL, severity: severity.INFORMATIONAL, confidence: confidence.TENTATIVE, properties: properties, manualReview: true };
  }

  isCspKey(key) {
    return typeof key === "string" && key.toLowerCase() === "content-security-policy";
  }

  // Returns the static string value of a header key node, or null when it cannot be determined (dynamic/ambiguous).
  resolveHeaderKey(keyNode, scope) {
    if (!keyNode) return null;
    if (keyNode.type === "Literal" || keyNode.type === "StringLiteral")
      return typeof keyNode.value === "string" ? keyNode.value : null;
    if (keyNode.type === "Identifier" && scope && typeof scope.getVarInScope === "function") {
      const variable = scope.getVarInScope(keyNode.name);
      const init = variable && variable.defs && variable.defs[0] && variable.defs[0].node && variable.defs[0].node.init;
      if (init && (init.type === "Literal" || init.type === "StringLiteral"))
        return typeof init.value === "string" ? init.value : null;
      return null;
    }
    return null;
  }

  resolveIdentifier(node, scope, seen) {
    if (!scope || typeof scope.getVarInScope !== "function") return null;
    const variable = scope.getVarInScope(node.name);
    if (!variable || !variable.defs || variable.defs.length === 0) return null;
    // A value that can be reassigned (including via update operators) cannot be trusted to still hold its
    // initializer at the point of use, so treat it as ambiguous and flag it for manual review. The write
    // performed by the variable declaration itself is not counted as a reassignment.
    const declarator = variable.defs[0].node;
    const hasReassignment = Array.isArray(variable.references) && variable.references.some(reference =>
      reference.isWrite() && reference.init !== true);
    if (hasReassignment) return null;
    if (declarator.type !== "VariableDeclarator" || !declarator.init) return null;
    if (seen.has(declarator)) return null;
    seen.add(declarator);
    return this.resolveNode(declarator.init, scope, seen);
  }

  // Returns the static CSP string, or null when the value is dynamic/ambiguous.
  resolveNode(node, scope, seen = new Set()) {
    if (!node) return null;
    if (node.type === "Literal" || node.type === "StringLiteral")
      return typeof node.value === "string" ? node.value : null;
    if (node.type === "TemplateLiteral") {
      if (node.expressions.length === 0 && node.quasis.length === 1)
        return node.quasis[0].value.cooked;
      return null;
    }
    if (node.type === "Identifier")
      return this.resolveIdentifier(node, scope, seen);
    if (node.type === "ArrayExpression") {
      if (node.elements.length === 0) return null;
      return this.resolveNode(node.elements[0], scope, seen);
    }
    return null;
  }

  resolveCspValue(valueNode, scope) {
    return this.resolveNode(valueNode, scope, new Set());
  }

  // Extracts CSP findings from a value reachable through an object spread or shorthand reference.
  extractFromSpread(referenceNode, locationNode, scope, seen = new Set()) {
    const findings = [];
    if (!referenceNode || referenceNode.type !== "Identifier" || !scope || typeof scope.getVarInScope !== "function")
      return findings;
    if (seen.has(referenceNode.name)) return findings;
    seen.add(referenceNode.name);

    const variable = scope.getVarInScope(referenceNode.name);
    // References that do not resolve to a local variable declaration (e.g. function parameters, globals) are
    // out of reach of static analysis and are already covered by the assignment-based checks when applicable.
    if (!variable || !variable.defs || variable.defs.length === 0) return findings;
    const declarator = variable.defs[0].node;
    if (declarator.type !== "VariableDeclarator" || !declarator.init) return findings;

    const init = declarator.init;
    if (init.type === "ObjectExpression") {
      for (const property of init.properties) {
        if (property.type === "SpreadElement" || property.type === "ExperimentalSpreadProperty") {
          for (const nested of this.extractFromSpread(property.argument, locationNode, scope, seen))
            findings.push(nested);
        } else {
          const headerKey = this.resolveHeaderKey(property.key, scope);
          if (headerKey === null) {
            findings.push(this.buildLocation(locationNode, null));
          } else if (this.isCspKey(headerKey)) {
            findings.push(this.buildLocation(locationNode, this.resolveCspValue(property.value, scope)));
          }
        }
      }
    } else if (init.type === "Identifier") {
      for (const nested of this.extractFromSpread(init, locationNode, scope, seen))
        findings.push(nested);
    }
    return findings;
  }
}
