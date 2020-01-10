var _class, _temp, _initialiseProps;

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

import t from 'prop-types';
import React from 'react';

function makeLookup(arr, prop) {
  var lkup = {};
  for (var i = 0, l = arr.length; i < l; i++) {
    if (prop) {
      lkup[arr[i][prop]] = true;
    } else {
      lkup[arr[i]] = true;
    }
  }
  return lkup;
}

function getItemsByProp(arr, prop, values) {
  var items = [];
  var found = 0;
  var valuesLookup = makeLookup(values);
  for (var i = 0, la = arr.length, lv = values.length; i < la && found < lv; i++) {
    if (valuesLookup[arr[i][prop]]) {
      items.push(arr[i]);
      found++;
    }
  }
  return items;
}

var DEFAULT_CLASS_NAMES = {
  button: 'FilteredMultiSelect__button',
  buttonActive: 'FilteredMultiSelect__button--active',
  filter: 'FilteredMultiSelect__filter',
  select: 'FilteredMultiSelect__select'
};

var FilteredMultiSelect = (_temp = _class = function (_React$Component) {
  _inherits(FilteredMultiSelect, _React$Component);

  function FilteredMultiSelect(props) {
    _classCallCheck(this, FilteredMultiSelect);

    var _this = _possibleConstructorReturn(this, _React$Component.call(this, props));

    _initialiseProps.call(_this);

    var defaultFilter = props.defaultFilter,
        selectedOptions = props.selectedOptions;

    _this.state = {
      // Filter text
      filter: defaultFilter,
      // Options which haven't been selected and match the filter text
      filteredOptions: _this._filterOptions(defaultFilter, selectedOptions),
      // Values of <options> currently selected in the <select>
      selectedValues: []
    };
    return _this;
  }

  FilteredMultiSelect.prototype.componentWillReceiveProps = function componentWillReceiveProps(nextProps) {
    // Update visible options in response to options or selectedOptions
    // changing. Also update selected values after the re-render completes, as
    // one of the previously selected options may have been removed.
    if (nextProps.options !== this.props.options || nextProps.selectedOptions !== this.props.selectedOptions || nextProps.options.length !== this.props.options.length || nextProps.selectedOptions.length !== this.props.selectedOptions.length) {
      this.setState({
        filteredOptions: this._filterOptions(this.state.filter, nextProps.selectedOptions, nextProps.options)
      }, this._updateSelectedValues);
    }
  };

  FilteredMultiSelect.prototype._getClassName = function _getClassName(name) {
    var classNames = [this.props.classNames[name] || DEFAULT_CLASS_NAMES[name]];

    for (var _len = arguments.length, modifiers = Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
      modifiers[_key - 1] = arguments[_key];
    }

    for (var i = 0, l = modifiers.length; i < l; i++) {
      if (modifiers[i]) {
        classNames.push(this.props.classNames[modifiers[i]] || DEFAULT_CLASS_NAMES[modifiers[i]]);
      }
    }
    return classNames.join(' ');
  };

  FilteredMultiSelect.prototype._filterOptions = function _filterOptions(filter, selectedOptions, options) {
    if (typeof filter == 'undefined') {
      filter = this.state.filter;
    }
    if (typeof selectedOptions == 'undefined') {
      selectedOptions = this.props.selectedOptions;
    }
    if (typeof options == 'undefined') {
      options = this.props.options;
    }
    filter = filter.toUpperCase();

    var _props = this.props,
        textProp = _props.textProp,
        valueProp = _props.valueProp;

    var selectedValueLookup = makeLookup(selectedOptions, valueProp);
    var filteredOptions = [];

    for (var i = 0, l = options.length; i < l; i++) {
      if (!selectedValueLookup[options[i][valueProp]] && (!filter || options[i][textProp].toUpperCase().indexOf(filter) !== -1)) {
        filteredOptions.push(options[i]);
      }
    }

    return filteredOptions;
  };

  /**
   * Adds backing objects for the currently selected options to the selection
   * and calls back with the new list.
   */


  FilteredMultiSelect.prototype.render = function render() {
    var _state = this.state,
        filter = _state.filter,
        filteredOptions = _state.filteredOptions,
        selectedValues = _state.selectedValues;
    var _props2 = this.props,
        className = _props2.className,
        disabled = _props2.disabled,
        placeholder = _props2.placeholder,
        showFilter = _props2.showFilter,
        size = _props2.size,
        textProp = _props2.textProp,
        valueProp = _props2.valueProp;

    var hasSelectedOptions = selectedValues.length > 0;
    return React.createElement(
      'div',
      { className: className },
      showFilter && React.createElement('input', {
        type: 'text',
        className: this._getClassName('filter'),
        placeholder: placeholder,
        value: filter,
        onChange: this._onFilterChange,
        onKeyPress: this._onFilterKeyPress,
        disabled: disabled
      }),
      React.createElement(
        'select',
        { multiple: true,
          ref: this._selectRef,
          className: this._getClassName('select'),
          size: size,
          value: selectedValues,
          onChange: this._updateSelectedValues,
          onDoubleClick: this._addSelectedToSelection,
          disabled: disabled },
        filteredOptions.map(function (option) {
          return React.createElement(
            'option',
            { key: option[valueProp], value: option[valueProp] },
            option[textProp]
          );
        })
      ),
      React.createElement(
        'button',
        { type: 'button',
          className: this._getClassName('button', hasSelectedOptions && 'buttonActive'),
          disabled: !hasSelectedOptions,
          onClick: this._addSelectedToSelection },
        this.props.buttonText
      )
    );
  };

  return FilteredMultiSelect;
}(React.Component), _class.defaultProps = {
  buttonText: 'Select',
  className: 'FilteredMultiSelect',
  classNames: {},
  defaultFilter: '',
  disabled: false,
  placeholder: 'type to filter',
  selectedOptions: [],
  showFilter: true,
  size: 6,
  textProp: 'text',
  valueProp: 'value'
}, _initialiseProps = function _initialiseProps() {
  var _this2 = this;

  this._selectRef = function (select) {
    _this2._select = select;
  };

  this._onFilterChange = function (e) {
    var filter = e.target.value;
    _this2.setState({
      filter: filter,
      filteredOptions: _this2._filterOptions(filter)
    }, _this2._updateSelectedValues);
  };

  this._onFilterKeyPress = function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (_this2.state.filteredOptions.length === 1) {
        var selectedOption = _this2.state.filteredOptions[0];
        var selectedOptions = _this2.props.selectedOptions.concat([selectedOption]);
        _this2.setState({ filter: '', selectedValues: [] }, function () {
          _this2.props.onChange(selectedOptions);
        });
      }
    }
  };

  this._updateSelectedValues = function (e) {
    var el = e ? e.target : _this2._select;
    var selectedValues = [];
    for (var i = 0, l = el.options.length; i < l; i++) {
      if (el.options[i].selected) {
        selectedValues.push(el.options[i].value);
      }
    }
    // Always update if we were handling an event, otherwise only update if
    // selectedValues has actually changed.
    if (e || String(_this2.state.selectedValues) !== String(selectedValues)) {
      _this2.setState({ selectedValues: selectedValues });
    }
  };

  this._addSelectedToSelection = function (e) {
    var selectedOptions = _this2.props.selectedOptions.concat(getItemsByProp(_this2.state.filteredOptions, _this2.props.valueProp, _this2.state.selectedValues));
    _this2.setState({ selectedValues: [] }, function () {
      _this2.props.onChange(selectedOptions);
    });
  };
}, _temp);
FilteredMultiSelect.propTypes = process.env.NODE_ENV !== "production" ? {
  onChange: t.func.isRequired,
  options: t.array.isRequired,

  buttonText: t.string,
  className: t.string,
  classNames: t.object,
  defaultFilter: t.string,
  disabled: t.bool,
  placeholder: t.string,
  selectedOptions: t.array,
  showFilter: t.bool,
  size: t.number,
  textProp: t.string,
  valueProp: t.string
} : {};


export default FilteredMultiSelect;