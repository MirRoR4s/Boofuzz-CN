from ..fuzzable_block import FuzzableBlock


class Block(FuzzableBlock):
    """
    基本的构造块（building block），可包含 primitives（原语）、sizers、checksums 以及其它 blocks。
    
    ..
     The basic building block. Can contain primitives, sizers, checksums or other blocks.

    :param name: 当前 blocks 的名称，默认为空
    :type name: str, optional
    :param default_value: 当元素不进行模糊测试时的默认值，通常应对应于一个有效的协议字段值，默认为空
    :type default_value: Any, optional
    :param request: 当前的 block 所属的 Request 对象，默认为空
    :type request: boofuzz.Request, optional
    :param children: 当前 blocks 的子节点，默认为空
    :type children: boofuzz.Fuzzable, optional
    :param group: 与当前的 block 相关联的 group 的名称，默认为空
    :type group: str, optional
    :param encoder: Optional pointer to a function to pass rendered data to prior to return, defaults to None
    :type encoder: callable, optional
    :param dep: Optional primitive whose specific value this block is dependant on, defaults to None
    :type dep: str, optional
    :param dep_value: Value that field "dep" must contain for block to be rendered, defaults to None
    :type dep_value: Any, optional
    :param dep_values: Values that field "dep" may contain for block to be rendered, defaults to None
    :type dep_values: list, optional
    :param dep_compare: Comparison method to apply to dependency (==, !=, >, >=, <, <=), defaults to None
    :type dep_compare: str, optional
    """

    def __init__(
        self,
        name=None,
        default_value=None,
        request=None,
        children=None,
        group=None,
        encoder=None,
        dep=None,
        dep_value=None,
        dep_values=None,
        dep_compare="==",
        *args,
        **kwargs
    ):
        super(Block, self).__init__(
            name=name, default_value=default_value, request=request, children=children, *args, **kwargs
        )

        self.request = request
        self.group = group
        self.encoder = encoder
        self.dep = dep
        self.dep_value = dep_value
        self.dep_values = dep_values
        self.dep_compare = dep_compare

        self._rendered = b""  # rendered block contents.
        self.group_idx = 0  # if this block is tied to a group, the index within that group.
        self._fuzz_complete = False  # whether or not we are done fuzzing this block.
        self._mutant_index = 0  # current mutation index.

    def mutations(self, default_value, skip_elements=None):
        for item in self.stack:
            self.request.mutant = item
            for mutations in item.get_mutations():
                yield mutations
        if self.group is not None:
            group = self.request.resolve_name(self.context_path, self.group)
            for group_mutations in group.get_mutations():
                for item in self.stack:
                    self.request.mutant = item
                    for mutations in item.get_mutations():
                        yield group_mutations + mutations

    def num_mutations(self, default_value=None):
        n = super(Block, self).num_mutations(default_value=default_value)
        if self.group is not None:
            n += n * self.request.resolve_name(self.context_path, self.group).get_num_mutations()
        return n

    def _do_dependencies_allow_render(self, mutation_context):
        if self.dep:
            dependent_value = self.request.resolve_name(self.context_path, self.dep).get_value(mutation_context)
            if self.dep_compare == "==":
                if self.dep_values and dependent_value not in self.dep_values:
                    return False
                elif not self.dep_values and dependent_value != self.dep_value:
                    return False

            if self.dep_compare == "!=":
                if self.dep_values and dependent_value in self.dep_values:
                    return False
                elif dependent_value == self.dep_value:
                    return False

            if self.dep_compare == ">" and self.dep_value <= dependent_value:
                return False

            if self.dep_compare == ">=" and self.dep_value < dependent_value:
                return False

            if self.dep_compare == "<" and self.dep_value >= dependent_value:
                return False

            if self.dep_compare == "<=" and self.dep_value > dependent_value:
                return False
        return True

    def encode(self, value, mutation_context):
        if self._do_dependencies_allow_render(mutation_context=mutation_context):
            child_data = super(Block, self).get_child_data(mutation_context=mutation_context)
        else:
            child_data = b""
        if self.encoder:
            return self.encoder(child_data)
        else:
            return child_data
